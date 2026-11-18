import re
from html import escape, unescape
from html.parser import HTMLParser

_VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})

_DROP_CONTENT_TAGS = frozenset({
    "script", "style", "iframe", "object", "applet", "frameset",
    "noframes", "noscript", "template", "xmp", "plaintext",
    "svg", "math",
})

_URL_ATTRS = frozenset({
    "href", "src", "action", "formaction", "xlink:href", "background",
    "cite", "data", "poster", "profile", "usemap", "dynsrc", "lowsrc",
})

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_URL_IGNORED = re.compile(r"[\x00-\x20\x7f-\xa0]")
_URL_BAD_CHARS = re.compile(r"[\s\"'<>`]")

_DEFAULT_TAGS = frozenset({"b", "i", "p", "a", "br"})
_DEFAULT_ATTRS = {"a": frozenset({"href"})}


def _is_safe_url(value):
    return _URL_IGNORED.sub("", value).lower().startswith("https://")


def _normalize_attrs(allowed_attrs, tags):
    if allowed_attrs is None:
        return {k: set(v) for k, v in _DEFAULT_ATTRS.items()}
    if isinstance(allowed_attrs, dict):
        return {
            str(tag).lower(): {str(attr).lower() for attr in attrs}
            for tag, attrs in allowed_attrs.items()
        }
    global_attrs = {str(attr).lower() for attr in allowed_attrs}
    return {tag: set(global_attrs) for tag in tags}


class _Sanitizer(HTMLParser):
    def __init__(self, allowed_tags, allowed_attrs):
        super().__init__(convert_charrefs=True)
        self.allowed_tags = allowed_tags
        self.allowed_attrs = allowed_attrs
        self.out = []
        self.open_tags = []
        self.drop_stack = []

    def handle_starttag(self, tag, attrs):
        if self.drop_stack:
            if tag in _DROP_CONTENT_TAGS and tag not in _VOID_TAGS:
                self.drop_stack.append(tag)
            return
        if tag in _DROP_CONTENT_TAGS and tag not in self.allowed_tags:
            if tag not in _VOID_TAGS:
                self.drop_stack.append(tag)
            return
        if tag not in self.allowed_tags:
            return
        self.out.append("<" + tag + self._clean_attrs(tag, attrs) + ">")
        if tag not in _VOID_TAGS:
            self.open_tags.append(tag)

    def handle_startendtag(self, tag, attrs):
        if self.drop_stack or tag not in self.allowed_tags:
            return
        if tag in _DROP_CONTENT_TAGS:
            return
        rendered = "<" + tag + self._clean_attrs(tag, attrs) + ">"
        self.out.append(rendered)
        if tag not in _VOID_TAGS:
            self.out.append("</" + tag + ">")

    def handle_endtag(self, tag):
        if self.drop_stack:
            if tag in _DROP_CONTENT_TAGS and tag in self.drop_stack:
                while self.drop_stack:
                    if self.drop_stack.pop() == tag:
                        break
            return
        if tag not in self.allowed_tags or tag in _VOID_TAGS:
            return
        if tag in self.open_tags:
            while self.open_tags:
                open_tag = self.open_tags.pop()
                self.out.append("</" + open_tag + ">")
                if open_tag == tag:
                    break

    def handle_data(self, data):
        if not self.drop_stack:
            self.out.append(escape(_CONTROL_CHARS.sub("", data)))

    def handle_entityref(self, name):
        if not self.drop_stack:
            self.out.append(escape(_CONTROL_CHARS.sub("", unescape("&" + name + ";"))))

    def handle_charref(self, name):
        if not self.drop_stack:
            self.out.append(escape(_CONTROL_CHARS.sub("", unescape("&#" + name + ";"))))

    def handle_comment(self, data):
        pass

    def handle_decl(self, decl):
        pass

    def handle_pi(self, data):
        pass

    def unknown_decl(self, data):
        pass

    def _clean_attrs(self, tag, attrs):
        allowed = self.allowed_attrs.get(tag, set()) | self.allowed_attrs.get("*", set())
        rendered = []
        seen = set()
        for name, value in attrs:
            name = name.lower()
            if name in seen or name not in allowed:
                continue
            seen.add(name)
            value = _CONTROL_CHARS.sub("", value or "")
            if name in _URL_ATTRS and (
                not _is_safe_url(value) or _URL_BAD_CHARS.search(value)
            ):
                continue
            rendered.append(' %s="%s"' % (name, escape(value, quote=True)))
        return "".join(rendered)

    def finish(self):
        while self.open_tags:
            self.out.append("</" + self.open_tags.pop() + ">")
        return "".join(self.out)


def sanitize(html, allowed_tags=None, allowed_attrs=None):
    if html is None:
        return ""
    if not isinstance(html, str):
        html = str(html)
    tags = {str(tag).lower() for tag in (allowed_tags or _DEFAULT_TAGS)}
    attrs = _normalize_attrs(allowed_attrs, tags)
    parser = _Sanitizer(tags, attrs)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return escape(_CONTROL_CHARS.sub("", html))
    return parser.finish()
