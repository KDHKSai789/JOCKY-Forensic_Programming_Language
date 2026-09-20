from compiler.compiler import Compiler


compiler = Compiler()

ir = compiler.compile_file("test.jocky")

print("\n=== COMPILATION SUCCESSFUL ===\n")

print("Case:")
print(ir.case_name)

print("\nTarget:")
print(ir.target)

print("\nInstructions:")

for instruction in ir.instructions:
    print(
        f"  {instruction.operation} "
        f"{instruction.arguments}"
    )
