"""Mouse-enabled terminal setup with explicit choices and one target text field."""
from __future__ import annotations

from urllib.parse import urlparse

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.data_structures import Point
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.filters import has_focus
from prompt_toolkit.layout import HSplit, VSplit, Layout, Window, DynamicContainer
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.processors import Processor, Transformation
from prompt_toolkit.mouse_events import MouseButton, MouseEventType
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Button, Frame, TextArea

from core.theme import BG, gradient_color
from core.clipboard import read_clipboard_text
from core.console_setup import mouse_input_mode


MODULE_OPTIONS = (
    ("waf", "WAF & CDN Detection"), ("ssl", "SSL / TLS Analysis"),
    ("recon", "Reconnaissance"), ("ports", "Port Scanning"),
    ("intel", "Easy-Win Discovery"), ("crawl", "Web Crawling"),
    ("js", "Deep JS Analysis"), ("extraction", "Data Extraction"),
    ("leaks", "Leak Scan"), ("headers", "Security Headers"),
    ("sqli", "SQL Injection"), ("xss", "XSS Testing"),
    ("vulns", "Vulnerability Audit"), ("auth", "Auth / Token Analysis"),
    ("protocol", "Protocol Analysis"), ("oob", "OOB Confirmation"),
    ("access", "Access Control"), ("api", "API Assessment"),
    ("spa", "SPA Analysis"), ("extended", "Extended Assessments"),
    ("plugins", "Configured Plugins"), ("bruteforce", "Directory Discovery"),
    ("discovery", "Discovery Expansion / Parameter Probing"),
)


def fragments(value):
    return [(f"fg:{gradient_color(index / max(1, len(value) - 1))}", char)
            for index, char in enumerate(value)]


class TargetGradient(Processor):
    def apply_transformation(self, transformation_input):
        text = "".join(fragment[1] for fragment in transformation_input.fragments)
        return Transformation(fragments(text))


class ChoiceList:
    def __init__(self, options, *, multiple=False, selected=None):
        self.options = list(options)
        self.multiple = multiple
        self.selected = set(selected or ())
        self.index = 0
        bindings = KeyBindings()
        @bindings.add("up")
        def up(event):
            self.index = max(0, self.index - 1)
        @bindings.add("down")
        def down(event):
            self.index = min(len(self.options) - 1, self.index + 1)
        @bindings.add("space")
        @bindings.add("enter")
        def choose(event):
            self.choose(self.index)
        self.control = FormattedTextControl(self.text, focusable=True, key_bindings=bindings,
                                            get_cursor_position=lambda: Point(0, self.index),
                                            show_cursor=False)
        self.window = Window(self.control, wrap_lines=False, style=f"bg:{BG}")

    @property
    def value(self):
        return next(iter(self.selected), None)

    def choose(self, index):
        self.index = index
        key = self.options[index][0]
        if self.multiple:
            if key in self.selected:
                self.selected.remove(key)
            else:
                self.selected.add(key)
        else:
            self.selected = {key}

    def mouse(self, index, event):
        if event.event_type == MouseEventType.MOUSE_UP:
            self.choose(index)
            get_app().layout.focus(self.control)
            get_app().invalidate()
        return None

    def text(self):
        output = []
        for index, (key, label) in enumerate(self.options):
            selected = key in self.selected
            marker = ("[x]" if selected else "[ ]") if self.multiple else ("(*)" if selected else "( )")
            color = gradient_color(index / max(1, len(self.options) - 1))
            style = f"fg:{color}"
            if index == self.index:
                style += " bold underline"
            handler = lambda event, row=index: self.mouse(row, event)
            output.append((style, f"  {marker}  {label}  ", handler))
            output.append(("", "\n"))
        return output[:-1]


class SetupWizard:
    TITLES = ("Select modules", "Safety mode", "Authorization", "Coverage profile", "Target URL / Domain")

    def __init__(self, *, input=None, output=None):
        self.page = 0
        self.message = ""
        self.modules = ChoiceList(MODULE_OPTIONS, multiple=True, selected=[key for key, _ in MODULE_OPTIONS])
        self.mode = ChoiceList((("safe", "Safe — read-oriented checks"),
                                ("active", "Active — injection and enumeration"),
                                ("intrusive", "Intrusive — additional protocol probes")), selected=["safe"])
        self.authorization = ChoiceList((("yes", "Yes"), ("no", "No")))
        self.profile = ChoiceList((("default", "Default"), ("deep", "Deep")), selected=["default"])
        self.target = TextArea(multiline=False, height=1, focus_on_click=True, complete_while_typing=False,
                               input_processors=[TargetGradient()],
                               accept_handler=lambda buffer: self.advance())
        self._paste_pending = False
        self._target_mouse = self.target.control.mouse_handler
        self.target.control.mouse_handler = self.target_mouse
        self.paste = Button("Paste", handler=self.paste_target)
        self.choices = (self.modules, self.mode, self.authorization, self.profile)
        for choice in self.choices:
            choice.window.width = self.content_width
        self.target.window.width = self.content_width
        self.back = Button("Back", handler=self.go_back)
        self.next = Button("Continue", handler=self.advance)
        self.cancel = Button("Cancel", handler=lambda: self.app.exit(result=None))
        self.full = Button("Full run", handler=self.select_all)
        self.clear = Button("Clear", handler=self.clear_modules)
        bindings = KeyBindings()
        @bindings.add("c-v", filter=has_focus(self.target))
        def paste(event):
            self.paste_target()
        @bindings.add("tab")
        def next_focus(event):
            event.app.layout.focus_next()
        @bindings.add("s-tab")
        def previous_focus(event):
            event.app.layout.focus_previous()
        @bindings.add("escape")
        @bindings.add("c-c")
        def cancel(event):
            event.app.exit(result=None)
        @bindings.add("f10")
        def advance(event):
            self.advance()
        self.layout = Layout(HSplit([
            Window(FormattedTextControl(lambda: fragments("K R Y P T O  //  SETUP")), height=2),
            Frame(DynamicContainer(self.body), title=lambda: self.TITLES[self.page], style="class:frame"),
            Window(FormattedTextControl(lambda: fragments(self.message)), height=2),
            VSplit([self.back, self.next, self.cancel], padding=3, height=1),
            Window(FormattedTextControl(lambda: fragments("Click to select  |  Tab: move  |  Esc: cancel")), height=2),
        ]), focused_element=self.modules.control)
        self.app = Application(layout=self.layout, key_bindings=bindings, full_screen=True,
                               mouse_support=True, color_depth=ColorDepth.DEPTH_24_BIT,
                               style=Style.from_dict({"": f"bg:{BG} fg:{gradient_color(0.4)}",
                                   "frame.border": gradient_color(0.0), "frame.label": gradient_color(0.15),
                                   "button": f"bg:{BG} fg:{gradient_color(0.75)}",
                                   "button.focused": f"bg:{BG} fg:{gradient_color(1.0)} bold underline",
                                   "selected-text": f"bg:{BG} fg:{gradient_color(1.0)} underline"}),
                               input=input, output=output)

    def body(self):
        if self.page == 0:
            return HSplit([VSplit([self.full, self.clear], padding=3, height=1),
                           self.modules.window,
                           Window(FormattedTextControl(fragments(
                               "Automatic: baseline, verification, correlation, impact, remediation, evidence and reports.")), height=2)],
                          width=self.content_width)
        if self.page == 2:
            return HSplit([Window(FormattedTextControl(fragments(
                "Do you own this target or have explicit permission to assess it?")), height=3),
                self.authorization.window], width=self.content_width)
        if self.page == 4:
            return HSplit([Window(FormattedTextControl(fragments("Enter the target URL or domain:")), height=3),
                           self.target, Window(height=1), self.paste,
                           Window(FormattedTextControl(fragments("Right-click in the field or Ctrl+V to paste.")), height=2),
                           Window()], width=self.content_width)
        return self.choices[self.page].window

    def content_width(self):
        return max(1, self.app.output.get_size().columns - 2)

    def focus_page(self):
        self.message = ""
        self.next.text = "Start scan" if self.page == 4 else "Continue"
        self.layout.focus(self.target if self.page == 4 else self.choices[self.page].control)
        self.app.invalidate()

    def go_back(self):
        self.page = max(0, self.page - 1)
        self.focus_page()

    def select_all(self):
        self.modules.selected = {key for key, _ in MODULE_OPTIONS}
        self.app.invalidate()

    def clear_modules(self):
        self.modules.selected.clear()
        self.app.invalidate()

    def paste_target(self):
        value = read_clipboard_text()
        if not value:
            value = self.app.clipboard.get_data().text
        value = value.strip().splitlines()[0] if value.strip() else ""
        value = "".join(char for char in value[:8192] if char.isprintable())
        if not value:
            self.message = "The clipboard has no text to paste."
        else:
            buffer = self.target.buffer
            if buffer.selection_state:
                buffer.cut_selection()
            buffer.insert_text(value)
            self.message = ""
        self.layout.focus(self.target)
        self.app.invalidate()

    def target_mouse(self, event):
        if event.button == MouseButton.RIGHT:
            if event.event_type == MouseEventType.MOUSE_DOWN:
                self.paste_target()
                self._paste_pending = True
            elif event.event_type == MouseEventType.MOUSE_UP:
                if not self._paste_pending:
                    self.paste_target()
                self._paste_pending = False
            return None
        if event.event_type == MouseEventType.MOUSE_UP and self._paste_pending:
            self._paste_pending = False
            return None
        return self._target_mouse(event)

    def result(self):
        target = self.target.text.strip()
        if not target or any(char.isspace() for char in target):
            raise ValueError("Enter a valid URL or domain without spaces.")
        parsed = urlparse(target if "://" in target else "https://" + target)
        try:
            valid = parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password
            parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Enter an HTTP(S) URL or domain, without embedded credentials.")
        stages = set(self.modules.selected)
        if stages & {"js", "bruteforce"}:
            stages.add("discovery")
        values = {"selected_stages": sorted(stages), "mode": self.mode.value,
                  "ack_authorized": self.authorization.value == "yes",
                  "deep": self.profile.value == "deep", "request_budget": None}
        for flag, stage in (("skip_ports", "ports"), ("skip_dirs", "bruteforce"),
                            ("skip_sqli", "sqli"), ("skip_xss", "xss"), ("skip_oob", "oob")):
            values[flag] = stage not in stages
        return target, values

    def advance(self):
        if self.page == 0 and not self.modules.selected:
            self.message = "Select at least one module, or choose Full run."
            return True
        if self.page == 2:
            if self.authorization.value is None:
                self.message = "Choose Yes or No."
                return True
            if self.authorization.value == "no":
                self.app.exit(result=None)
                return True
        if self.page < 4:
            self.page += 1
            self.focus_page()
        else:
            try:
                result = self.result()
            except ValueError as error:
                self.message = str(error)
            else:
                self.app.exit(result=result)
        return True

    def run(self, pre_run=None):
        with mouse_input_mode():
            return self.app.run(pre_run=pre_run)


def run_setup():
    return SetupWizard().run()
