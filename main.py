from analyzer import analyze_code

def read_file(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def run_analysis(file_path):
    code = read_file(file_path)
    issues = analyze_code(code)

    print(f"\nAnalyzing: {file_path}")
    print("="*40)

    if not issues:
        print("✅ No vulnerabilities found!")
    else:
        for i, issue in enumerate(issues, 1):
            print(f"\n⚠️ Issue {i}:")
            print(f"Type: {issue['type']}")
            print(f"Message: {issue['message']}")
            print(f"Fix: {issue['fix']}")

if __name__ == "__main__":
    run_analysis("test_code/vulnerable.c")
    run_analysis("test_code/vulnerable.py")