import pytest

from backend.core.cancellation import CancelToken
from backend.engines.base import EngineContext
from backend.engines.inventory import build_inventory
from backend.engines.javascript import JavaScriptEngine, strip_comments


def _scan(make_tree, settings, files):
    root = make_tree(files)
    inventory = build_inventory(root, settings.max_scan_file_bytes)
    return JavaScriptEngine().run(EngineContext(root=root, inventory=inventory, settings=settings,
                                                token=CancelToken()))


@pytest.mark.parametrize("line, rule", [
    ("eval(userInput);", "JS001"),
    ("const f = new Function('a', body);", "JS002"),
    ("setTimeout('doThing()', 100);", "JS003"),
    ("el.innerHTML = data;", "JS004"),
    ("el.insertAdjacentHTML('beforeend', html);", "JS005"),
    ("document.write(msg);", "JS006"),
    ("<div dangerouslySetInnerHTML={{__html: raw}} />", "JS007"),
    ("exec(`ls ${req.query.dir}`);", "JS008"),
    ("child_process.execSync('rm ' + target);", "JS008"),
    ("spawn('sh', args, { shell: true });", "JS009"),
    ("db.query(\"SELECT * FROM users WHERE id = \" + id);", "JS010"),
    ("pool.query(`DELETE FROM t WHERE id = ${id}`);", "JS010"),
    ("new https.Agent({ rejectUnauthorized: false });", "JS011"),
    ("crypto.createHash('md5').update(pw);", "JS012"),
    ("const token = Math.random().toString(36);", "JS013"),
    ("jwt.verify(t, key, { algorithms: ['none'] });", "JS014"),
    ("jwt.verify(t, key, { ignoreExpiration: true });", "JS015"),
    ("jwt.sign(payload, 'supersecretvalue');", "JS016"),
    ("app.use(cors({ origin: '*' }));", "JS017"),
    ("target['__proto__'] = value;", "JS018"),
    ("serialize.unserialize(body);", "JS019"),
    ("vm.runInNewContext(code);", "JS020"),
    ("res.redirect(req.query.next);", "JS021"),
    ("res.send(req.query.name);", "JS022"),
    ("fs.readFile(req.params.file, cb);", "JS023"),
    ("localStorage.setItem('authToken', t);", "JS024"),
    ("window.parent.postMessage(data, '*');", "JS025"),
])
def test_each_rule_fires(make_tree, settings, line, rule):
    result = _scan(make_tree, settings, {"app.js": line + "\n"})
    assert [f.rule_id for f in result.findings] == [rule]
    finding = result.findings[0]
    assert finding.line == 1 and finding.file_path == "app.js" and finding.cwe


@pytest.mark.parametrize("line", [
    "// eval(userInput);",
    "/* el.innerHTML = data; */",
    "const m = /a+/.exec(text);",
    "el.innerHTML = '';",
    "el.innerHTML = DOMPurify.sanitize(html);",
    "const s = 'use eval( carefully';",
    "if (a.innerHTML == b) {}",
])
def test_safe_code_is_not_flagged(make_tree, settings, line):
    assert _scan(make_tree, settings, {"app.js": line + "\n"}).findings == []


def test_block_comments_spanning_lines_and_minified_files(make_tree, settings):
    files = {
        "a.ts": "/*\n eval(x)\n*/\nconst y = 1;\n",
        "bundle.min.js": "eval(x)",
        "dense.js": ("var a=eval(b);" * 60 + "\n") * 20,
    }
    result = _scan(make_tree, settings, files)
    assert result.findings == []
    assert any("minified" in note for note in result.notes)


def test_strip_comments_respects_strings():
    code, masked, in_block = strip_comments("const url = 'http://x'; // note", False)
    assert code.strip() == "const url = 'http://x';" and not in_block
    assert masked.strip() == "const url = '        ';"
    code, _, in_block = strip_comments("a(); /* start", False)
    assert code.strip() == "a();" and in_block
    code, _, in_block = strip_comments("end */ b();", True)
    assert code.strip() == "b();" and not in_block
