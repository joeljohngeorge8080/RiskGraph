// Joern taint query for the X4.0 spike (L-2). Reads a code property graph, finds flows from
// request data to the sinks of the RiskGraph catalogue, and writes one line per sink:
//   <class id>\t<file>\t<line>\t<steps: file:line;file:line;...>
// Run: joern --script taint.sc --param cpgFile=<cpg.bin> --param out=<file> --param lang=py|js
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import java.nio.file.{Files, Paths}
import scala.util.Try

@main def exec(cpgFile: String, out: String, lang: String = "py"): Unit = {
  importCpg(cpgFile)

  // class id -> (sink call regex, sanitizer regex), the same classes as taint_catalogue.yaml
  val classes: List[(String, String, String)] =
    if (lang == "py") List(
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
    ) else List(
      ("sql-injection", ".*\\.(query|raw|execute)\\(.*", "(parseInt|Number)\\(.*"),
      ("os-command-injection", "(child_process\\.)?(exec|execSync|spawn)\\(.*", "$^"),
      ("code-injection", "(eval|Function)\\(.*", "$^"),
      ("path-traversal", "(fs\\.)?(readFile|readFileSync|createReadStream)\\(.*", "path\\.basename\\(.*")
    )

  val sourceRegex =
    if (lang == "py") ".*request\\.(args|form|values|json|data|files|cookies|headers|get_json)\\b.*"
    else ".*req\\.(query|body|params|cookies|headers)\\b.*"

  val sources = cpg.call.code(sourceRegex).l
  val found = scala.collection.mutable.LinkedHashSet[String]()
  for ((id, sinkRegex, sanRegex) <- classes) {
    val sinks = cpg.call.code(sinkRegex).argument.filter(_.argumentIndex > 0).l
    if (sources.nonEmpty && sinks.nonEmpty) {
      sinks.reachableByFlows(sources).foreach { path =>
        // a sanitizer is the element itself or the call that wraps it (int(x), os.path.basename(x))
        // (anywhere in the element's code: str(int(x)) is still sanitized)
        val inCode = ".*\\b" + sanRegex
        val sanitized = path.elements.exists(e =>
          e.code.matches(inCode) || Try(e.astParent.code.matches(inCode)).getOrElse(false))
        if (!sanitized) {
          val last = path.elements.last
          // locations only, never code (ADR-0021): file:line;file:line;... from source to sink
          val steps = path.elements
            .map(e => s"${e.file.name.headOption.getOrElse("")}:${e.lineNumber.getOrElse(0)}")
            .mkString(";")
          found += s"$id\t${last.file.name.headOption.getOrElse("")}\t${last.lineNumber.getOrElse(0)}\t$steps"
        }
      }
    }
  }
  Files.write(Paths.get(out), found.mkString("\n").getBytes("UTF-8"))
}
