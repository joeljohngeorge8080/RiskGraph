"""Package (distribution) name → import names (blueprint §11.3 "name-mapping table").

npm packages are imported by their package name. PyPI distributions often are not
(``PyYAML`` → ``yaml``); the curated table covers common mismatches, otherwise the name
is normalized (lower case, ``-``/``.`` → ``_``).
"""

from __future__ import annotations

import re

PYPI_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "python-dateutil": ("dateutil",),
    "pyjwt": ("jwt",),
    "psycopg2-binary": ("psycopg2",),
    "psycopg-binary": ("psycopg",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "protobuf": ("google.protobuf",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pyopenssl": ("OpenSSL",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart", "python_multipart"),
    "python-dotenv": ("dotenv",),
    "attrs": ("attr", "attrs"),
    "msgpack-python": ("msgpack",),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "setuptools": ("setuptools", "pkg_resources"),
    "google-cloud-storage": ("google.cloud.storage",),
    "markupsafe": ("markupsafe",),
    "jinja2": ("jinja2",),
    "django-rest-framework": ("rest_framework",),
    "djangorestframework": ("rest_framework",),
    "flask-sqlalchemy": ("flask_sqlalchemy",),
    "sqlalchemy": ("sqlalchemy",),
    "typing-extensions": ("typing_extensions",),
    "websocket-client": ("websocket",),
    "ruamel.yaml": ("ruamel.yaml",),
    "mysql-connector-python": ("mysql.connector",),
    "mysqlclient": ("MySQLdb",),
    "pywin32": ("win32api", "win32con"),
}

# Used without being imported (CLIs, servers, plugins, build tools): "not imported"
# proves nothing, so these never get L0.
USED_WITHOUT_IMPORT = frozenset(
    {
        # python
        "gunicorn",
        "uvicorn",
        "hypercorn",
        "daphne",
        "waitress",
        "supervisor",
        "pip",
        "setuptools",
        "wheel",
        "pytest",
        "tox",
        "nox",
        "coverage",
        "black",
        "flake8",
        "pylint",
        "mypy",
        "ruff",
        "isort",
        "pre-commit",
        "alembic",
        "celery",
        "ansible",
        "awscli",
        "honcho",
        # npm
        "typescript",
        "webpack",
        "webpack-cli",
        "vite",
        "rollup",
        "esbuild",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "nodemon",
        "pm2",
        "ts-node",
        "tsx",
        "next",
        "react-scripts",
        "gulp",
        "grunt",
        "npm",
        "yarn",
        "pnpm",
        "forever",
        "concurrently",
        "cross-env",
        "rimraf",
        "npm-run-all",
        "husky",
        "lint-staged",
        "http-server",
        "serve",
        "karma",
        "cypress",
        "grunt-cli",
        "bower",
    }
)
_USED_WITHOUT_IMPORT_PREFIXES = (
    "pytest-",
    "flake8-",
    "types-",
    "django-",  # Django apps are wired through INSTALLED_APPS strings
    "@types/",
    "@babel/",
    "babel-",
    "eslint-",
    "@eslint/",
    "@typescript-eslint/",
    "webpack-",
    "postcss",
    "tailwindcss",
    "@vitejs/",
    "vite-plugin-",
)

PYTHON_ECOSYSTEMS = frozenset({"pip", "pipenv", "poetry", "uv", "pdm", "python-pkg", "conda-pkg"})
NPM_ECOSYSTEMS = frozenset({"npm", "yarn", "pnpm", "bun", "node-pkg"})


def used_without_import(name: str) -> bool:
    n = name.lower()
    return n in USED_WITHOUT_IMPORT or n.startswith(_USED_WITHOUT_IMPORT_PREFIXES)


def python_import_names(distribution: str) -> tuple[str, ...]:
    key = distribution.lower()
    if key in PYPI_IMPORT_NAMES:
        return PYPI_IMPORT_NAMES[key]
    normalized = re.sub(r"[-.]+", "_", key)
    return (normalized,) if normalized == key else (normalized, key)


def import_names(ecosystem: str | None, package: str) -> tuple[str, ...] | None:
    """Names to look for in imports, or None when the ecosystem is not analysed."""
    eco = (ecosystem or "").lower()
    if eco in PYTHON_ECOSYSTEMS:
        return python_import_names(package)
    if eco in NPM_ECOSYSTEMS:
        return (package,)
    return None
