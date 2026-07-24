import ast
from pathlib import Path


def test_subscription_client_parameter_annotations():
    source = Path("lib/rucio/client/subscriptionclient.py").read_text()
    tree = ast.parse(source)
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    def annotation(function, parameter):
        argument = next(arg for arg in functions[function].args.args if arg.arg == parameter)
        return ast.unparse(argument.annotation) if argument.annotation else None

    assert annotation("add_subscription", "replication_rules") == "list[dict[str, Any]]"
    assert annotation("update_subscription", "replication_rules") == "Optional[list[dict[str, Any]]]"
    assert annotation("update_subscription", "name") == "str"
    assert annotation("list_subscriptions", "account") == "Optional[str]"
