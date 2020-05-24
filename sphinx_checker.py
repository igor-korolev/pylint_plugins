"""
Pylint checker examines code documentation according to python sphinx format.
"""

import collections
import itertools
import re

from pylint.checkers import BaseChecker, utils
from pylint.interfaces import IAstroidChecker


BUILTINS = "builtins"

_MAIN = "main"
_RETURNS = ":returns"
_RAISES = ":raises"
_PARAM = ":param"
_TYPE = ":type"

SPHINX_KEYWORDS = {_RETURNS, _RAISES, _PARAM, _TYPE}
NOT_NEEDED_PARAMS = {"self", "cls"}

RE_DOC_RETURNS = r":returns: .+"
RE_DOC_PARAM = r":param (?:\w+\s)*({}): .+"
RE_DOC_RAISES = r":raises .+: .+"
RE_DOC_ASSERTION_RAISES = r":raises AssertionError: .+"

MISSED_PARAM = "missed-doc-param"
MISSED_RETURN = "missed-doc-returns"
MISSED_RAISES = "missed-doc-raises"
MISSED_ASSERTION_RAISES = "missed-assert-raises"
MISSED_MAIN_DOC = "missed-main-doc-block"
WRONG_RETURN_ENDING = "doc-wrong-return-ending"
WRONG_RAISE_ENDING = "wrong-raises-ending"
WRONG_RAISE_FORMAT = "wrong-raises-format"
EXCESS_PARAM = "excess-param-in-doc"
EXCESS_EMPTY_LINE = "excess-empty-line"
SEPARATE_BLOCK = "block-doc-empty-line"
NO_DOT_AT_THE_END = "no-dot-at-the-end"
# TODO: Add check on empty lines before and after class docs

_ADDITIONAL_ERROR_INFO = "Refer to the project rules on wiki"


def is_init(method_name):
    """
    Identify whether provided method is standard 'init' constructor or not.

    :param str method_name: The method name to check.

    :returns: Boolean - True if given method is 'init'.
    """
    return method_name == "__init__"


def is_magic_method(method_name):
    """
    Determine if passed method is special python method.

    :param str method_name: The method name to check.

    :returns: Boolean - True if given method is magic.
    """
    # Init has to be documented appropriately, so we ignore it
    return method_name.startswith("__") and method_name.endswith("__") and not is_init(method_name)


def is_test(func_name):
    """
    We don't describe params in tests, so it's important to check node's name first.

    :param str func_name: Full name of a function/method.

    :returns: Boolean True if given function/method is test.
    """
    return func_name.startswith("test_")


def parse_sphinx_docs(doc):
    """
    Take appart the documentation by sphinx keywords.

    :param str doc: Documentation of some function/method.

    :returns: Dict with parsed documentation.
    """
    # TODO: Add :type to verification someday
    sphinx_keys_pattern = re.compile("|".join(SPHINX_KEYWORDS - {_TYPE}))
    found_keys = list(re.finditer(sphinx_keys_pattern, doc))
    if not found_keys:
        return {_MAIN: doc}
    doc_parts = collections.OrderedDict()
    main_doc = doc[: found_keys[0].start()]
    if main_doc.strip():
        doc_parts[_MAIN] = main_doc

    def arrange_parts(key, doc_part):
        """
        Helper function to place documentation part to right place in result dict.

        :param str key: The key, that will represent sphinx keyword in result dict.
        :param str doc_part: Any found by sphinx keywords documentation part.
        """
        if key == _PARAM:
            doc_parts.setdefault(_PARAM, []).append(doc_part)
        elif key == _RAISES:
            doc_parts.setdefault(_RAISES, []).append(doc_part)
        else:
            doc_parts[key] = doc_part

    for first, second in itertools.zip_longest(found_keys, found_keys[1:]):
        if second is not None:
            arrange_parts(first.group(), doc[first.start() : second.start()])
        else:
            # process the last element(from the last regexp found index to the end of docs)
            arrange_parts(first.group(), doc[first.start() :])
    return doc_parts


class SphinxDocsChecker(BaseChecker):

    """Custom sphinx documentation checker."""

    __implements__ = IAstroidChecker

    name = "sphinx-documentation-checker"

    msgs = {
        "C5001": (
            '"%s" parameter is defined in "%s", but it is not described in docs.',
            MISSED_PARAM,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5002": (
            '"%s" has "return" statement(s), but it is not described in docs.',
            MISSED_RETURN,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5003": (
            '":return:" should be replaced with ":returns:" in %s',
            WRONG_RETURN_ENDING,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5004": (
            '"%s" has "raise" statement, but not described in docs.',
            MISSED_RAISES,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5005": (
            '":raise:" should be replaced with ":raises:" in %s',
            WRONG_RAISE_ENDING,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5006": (
            '":raises" has format: ":raises SomeError: ..." in %s',
            WRONG_RAISE_FORMAT,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5007": (
            'Documentation blocks in "%s" should be divided using empty line:'
            '\n\t"%s" <-- add an empty line here!',
            SEPARATE_BLOCK,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5008": (
            '"%s" documentation contains excess parameters: "%s".',
            EXCESS_PARAM,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5009": (
            '"%s" documentation contains excess empty lines.',
            EXCESS_EMPTY_LINE,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5010": (
            '"%s" is missing main documentation block.',
            MISSED_MAIN_DOC,
            _ADDITIONAL_ERROR_INFO,
        ),
        "C5011": ('"%s" should end with a dot.', NO_DOT_AT_THE_END, _ADDITIONAL_ERROR_INFO),
        "C5012": (
            '"%s" contains "assert" statement, but it is not described in docs.',
            MISSED_ASSERTION_RAISES,
            _ADDITIONAL_ERROR_INFO,
        ),
    }

    options = ()

    priority = -1

    def visit_functiondef(self, node):
        """
        Standard pylint visitor method to get AST representation of some function/method.

        :param node: This parameter will have value of AST representation of visited function.
        """
        if node.doc is None or is_magic_method(node.name) or is_test(node.name):
            return

        self._check_main_block(node)
        self._check_doc_params(node)
        self._check_excess_empty_lines(node)
        self._check_blocks_separated_with_empty_line(node)
        self._check_dot_at_the_end(node)

    def visit_return(self, node):
        """
        Standard pylint visitor method to get current 'return' AST representation.

        :param node: Parameter will have AST representation of visited function 'return' statement.
        """
        frame = node.frame()
        if frame.doc is None or is_magic_method(frame.name):
            return
        if not self._is_node_none(node):
            self._check_doc_returns(frame)

    def visit_raise(self, node):
        """
        Standard pylint visitor method to get all current 'raise' AST representation.

        :param node: Parameter will have AST representation of visited function 'raise' statement.
        """
        frame = node.frame()
        raised_exception = ""
        try:
            raised_exception = node.exc.func.name
        except AttributeError as _:  # In case of bare 'raise' without speceifying exception name
            pass
        ignore = utils.node_ignores_exception
        is_ignored_in_except_block = ignore(node, raised_exception) or ignore(node, Exception)

        if (
            frame.doc is None
            or is_magic_method(frame.name)
            or is_test(frame.name)
            or is_ignored_in_except_block
        ):
            return

        if not self._is_node_none(node):
            self._check_doc_raises(frame)

    def visit_assert(self, node):
        """
        Standard pylint visitor method to get all current 'assert' statements as AST representation.

        :param node: Parameter will have AST representation of visited function 'assert' statement.
        """
        docs = node.frame().doc
        if docs:
            self._check_assert_raises_in_docs(node, docs)

    def _check_assert_raises_in_docs(self, node, docs):
        """
        Verify that 'assert' statements is documented properly.

        :param node: Parameter will have AST representation of visited function 'assert' statement.
        :param str docs: Function/method documentation to check.
        """
        func_name = node.frame().name
        ignore = utils.node_ignores_exception
        is_ignored_in_except_block = ignore(node, AssertionError) or ignore(node, Exception)
        # If function is our test or try/except suppresses assertion, then we ignore checks
        if is_test(func_name) or is_ignored_in_except_block:
            return
        if not self._is_in_docs(RE_DOC_ASSERTION_RAISES, docs):
            self.add_message(MISSED_ASSERTION_RAISES, node=node, args=(func_name,))

    @staticmethod
    def _is_in_docs(item, docs):
        """
        Helper function to determine if documentation contains given item.

        :param str item: Some peace of documentation(should be regexp).
        :param str docs: Full function/method documentation(__doc__).

        :returns: A boolean value with a verdict - the documentation contains element or not.
        """
        return re.search(item, docs) is not None

    @staticmethod
    def _is_node_none(node):
        """
        Helper method to identify, that the node is not None.

        :param node: Can be any AST object(e.g. function, method, class etc).

        :returns: True if node is None, False otherwise.
        """
        try:
            return node.value is None or node.value.pytype() == BUILTINS + ".NoneType"
        except AttributeError as _:  # pylint: disable=unused-variable
            return False  # When return value is some callable

    def _check_main_block(self, node):
        """
        Examine and verify the main part is documented properly.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        is_main_doc_needed = True
        if utils.decorated_with_property(node) or is_init(node.name):
            is_main_doc_needed = False

        if is_main_doc_needed and _MAIN not in parse_sphinx_docs(node.doc):
            self.add_message(MISSED_MAIN_DOC, node=node, args=(node.name,))

    def _check_doc_returns(self, node):
        """
        Verify that 'return' statements is documented properly.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        if not self._is_in_docs(RE_DOC_RETURNS, node.doc):
            if ":return:" in node.doc:  # Our common convention mistake
                self.add_message(WRONG_RETURN_ENDING, node=node, args=(node.name,))
            else:
                self.add_message(MISSED_RETURN, node=node, args=(node.name,))

    def _check_doc_raises(self, node):
        """
        Verify that 'raise' statements is documented properly.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        docs = node.doc
        if not self._is_in_docs(RE_DOC_RAISES, docs):
            if ":raise:" in docs:  # Our common convention mistake
                self.add_message(WRONG_RAISE_ENDING, node=node, args=(node.name,))
            elif ":raises:" in docs:
                self.add_message(WRONG_RAISE_FORMAT, node=node, args=(node.name,))
            else:
                self.add_message(MISSED_RAISES, node=node, args=(node.name,))

    def _check_doc_params(self, node):
        """
        Verify that parameters of node is documented properly.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        function_args = [arg.name.strip("*") for arg in node.args.args if arg.name not in NOT_NEEDED_PARAMS]
        for arg in function_args:
            if not self._is_in_docs(RE_DOC_PARAM.format(arg), node.doc):
                self.add_message(MISSED_PARAM, node=node, args=(arg, node.name))
        if function_args:
            self._check_excess_doc_params(node, function_args)

    def _check_excess_doc_params(self, node, args):
        """
        Helper method to identify unwanted parameters in documentation (not in signature).

        :param node: Can be any AST object(e.g. function, method, class etc).
        :param args: Arguments to pass to the pylint message.
        """
        docs_params = set(re.findall(RE_DOC_PARAM.format(r"\w+"), node.doc))
        excess_params = docs_params.difference(args)
        if excess_params:
            self.add_message(EXCESS_PARAM, node=node, args=(node.name, excess_params))

    def _check_excess_empty_lines(self, node):
        """
        Analyze documentation and find any unneeded new lines between documentation blocks.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        lines = [line.strip() for line in node.doc.split("\n")]
        if lines[0] == "":
            lines = lines[1:]  # Ignore: docs can begin from the new line

        if len(lines) == 1:  # If one-line documentation, exit immediately
            return

        if lines[0] == "" or lines[-2:] == ["", ""]:
            self.add_message(EXCESS_EMPTY_LINE, node=node, args=(node.name,))

    def _check_blocks_separated_with_empty_line(self, node):
        """
        Check, that documentation blocks are divided by an empty line.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        parsed_doc = parse_sphinx_docs(node.doc)
        for block in list(parsed_doc.values())[:-1]:  # empty line not needed in the last block
            if isinstance(block, list):
                block_to_check = block[-1].rstrip(" ")
            else:
                block_to_check = block.rstrip(" ")
            if not block_to_check.endswith("\n\n"):
                self.add_message(
                    SEPARATE_BLOCK, node=node, args=(node.name, block_to_check.strip())
                )

    def _check_dot_at_the_end(self, node):
        """
        Check, that every documentation block ends with a period.

        :param node: Can be any AST object(e.g. function, method, class etc).
        """
        parsed_doc = parse_sphinx_docs(node.doc)

        def verify_dot(part):
            """
            Helper function to check that provided documentation part ends with a dot.

            :param str part: Any documentation part.
            """
            if not part.endswith("."):
                self.add_message(NO_DOT_AT_THE_END, node=node, args=(part,))

        for doc_part in list(parsed_doc.values()):
            if isinstance(doc_part, list):
                for subpart in doc_part:
                    verify_dot(subpart.strip())
            else:
                verify_dot(doc_part.strip())


def register(linter):
    """
    Required method to auto register this checker.

    :param linter: An object implementing ILinter.
    """
    linter.register_checker(SphinxDocsChecker(linter))
