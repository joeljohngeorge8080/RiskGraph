// RiskGraph tier-2 taint query (X4 part 2, ADR-0021, ADR-0025). Vendored into
// riskgraph/scanner-joern; the adapter runs it as one command (no shell):
//
//   joern --script taint.sc --param src=<checkout> --param out=<report.json>
//         --param lookups=<regex> [--param lang=py]
//
// It parses the checkout into a code property graph (importCode: the workspace goes under
// the working directory, which the adapter sets to the scanner's private HOME), finds flows
// from request data to the sinks of the five classes of taint_catalogue.yaml, drops a flow
// when a sanitizer appears on it, and writes JSON:
//
//   {"version": 1, "language": "py", "flows": [
//     {"class": "<class id>", "sink": {"file": "...", "line": N},
//      "steps": [{"file": "...", "line": N}, ...]}]}   // source first, sink last
//
// Locations only, never code (ADR-0021). Class ids and sink lists must match the
// catalogue's python entries; backend/tests/test_joern_query.py keeps them in step.
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import java.nio.file.{Files, Paths}
import scala.util.Try

def jsonString(s: String): String = {
  val b = new StringBuilder("\"")
  s.foreach {
    case '"'  => b.append("\\\"")
    case '\\' => b.append("\\\\")
    case '\n' => b.append("\\n")
    case '\r' => b.append("\\r")
    case '\t' => b.append("\\t")
    case c if c < ' ' => b.append(f"\\u${c.toInt}%04x")
    case c => b.append(c)
  }
  b.append("\"").toString
}

def loc(file: String, line: Int): String =
  s"""{"file": ${jsonString(file)}, "line": $line}"""

@main def exec(src: String, out: String, lookups: String, lang: String = "py"): Unit = {
  if (lang != "py") {
    // tier 2 is Python only (expansion plan §5, MVE); other languages are not parsed
    Files.write(Paths.get(out), s"""{"version": 1, "language": ${jsonString(lang)}, "flows": []}""".getBytes("UTF-8"))
    return
  }
  importCode(inputPath = src, projectName = "riskgraph", language = "PYTHONSRC")

  // class id -> (sink call regex, sanitizer regex): the catalogue's python classes
  val classes: List[(String, String, String)] = List(
    ("sql-injection", ".*\\.(execute|executemany)\\(.*|sqlalchemy\\.text\\(.*|.*\\.objects\\.raw\\(.*",
      "(int|float)\\(.*"),
    ("os-command-injection",
      "(os\\.(system|popen)|subprocess\\.(getoutput|getstatusoutput|run|call|check_call|check_output|Popen))\\(.*",
      "shlex\\.quote\\(.*"),
    ("path-traversal", "((io\\.)?open|flask\\.send_file|os\\.remove|os\\.unlink)\\(.*",
      "(os\\.path\\.basename|werkzeug\\.utils\\.secure_filename|secure_filename)\\(.*"),
    ("unsafe-deserialization", "(pickle\\.(loads|load)|marshal\\.loads|yaml\\.(load|unsafe_load))\\(.*", "$^"),
    ("server-side-request-forgery",
      "((requests|httpx)\\.(get|post|put|patch|delete|head)|urllib\\.request\\.urlopen)\\(.*", "$^")
  )
  val sourceRegex = ".*request\\.(args|form|values|json|data|files|cookies|headers|get_json)\\b.*"
  // an allow-list lookup (catalogue: lookup_sanitizers): the flow passes THROUGH a lookup
  // call on a constant mapping (ALLOWED.get(x), ALLOWED[x]), so what flows on is one of the
  // mapping's own values. Structural on purpose: in CONFIG["base"] + x the lookup is not on
  // x's path, so x stays tainted.
  val lookupReceiver = "(" + lookups + ").*"
  def isLookup(e: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean =
    Try {
      val call = e.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
      (call.name == "get" || call.name == "<operator>.indexAccess") &&
        call.code.matches(lookupReceiver)
    }.getOrElse(false)

  val sources = cpg.call.code(sourceRegex).l
  val flows = scala.collection.mutable.LinkedHashSet[String]()
  for ((id, sinkRegex, sanRegex) <- classes) {
    val sinks = cpg.call.code(sinkRegex).argument.filter(_.argumentIndex > 0).l
    if (sources.nonEmpty && sinks.nonEmpty) {
      sinks.reachableByFlows(sources).foreach { path =>
        // a sanitizer is the element itself or the call that wraps it, anywhere in its code
        // (str(int(x)) is still sanitized)
        val inCode = ".*\\b" + sanRegex
        val sanitized = path.elements.exists(e =>
          e.code.matches(inCode) || Try(e.astParent.code.matches(inCode)).getOrElse(false) ||
            isLookup(e))
        if (!sanitized) {
          val steps = path.elements.map(e =>
            loc(e.file.name.headOption.getOrElse(""), e.lineNumber.getOrElse(0)))
          // consecutive duplicates (several elements on one line) say nothing more
          val compact = steps.foldLeft(List.empty[String])((acc, s) =>
            if (acc.headOption.contains(s)) acc else s :: acc).reverse
          val last = path.elements.last
          val sink = loc(last.file.name.headOption.getOrElse(""), last.lineNumber.getOrElse(0))
          flows += s"""{"class": ${jsonString(id)}, "sink": $sink, "steps": [${compact.mkString(", ")}]}"""
        }
      }
    }
  }
  val doc = s"""{"version": 1, "language": "py", "flows": [${flows.mkString(", ")}]}"""
  Files.write(Paths.get(out), doc.getBytes("UTF-8"))
}
