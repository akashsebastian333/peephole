import ast
import operator
from flask import Flask, request

app = Flask(__name__)

class SafeEvaluator(ast.NodeVisitor):
    OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }

    def visit_BinOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)
        op = self.OPERATORS[type(node.op)]
        return op(left, right)

    def visit_UnaryOp(self, node):
        op = self.OPERATORS[type(node.op)]
        operand = self.visit(node.operand)
        return op(operand)

    def visit_Constant(self, node):
        return node.value

    def visit_Num(self, node):
        return node.n

def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    return SafeEvaluator().visit(tree.body)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = safe_eval(expr)
        return {"result": result}
    except Exception as e:
        return {"error": str(e)}, 400

if __name__ == '__main__':
    app.run()
