import sys
import re

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/wwwroot/index.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Find the main script block
scripts = list(re.finditer(r'<script>(.*?)</script>', content, re.DOTALL))
print(f"Found {len(scripts)} inline script block(s)")

if scripts:
    main_script = scripts[-1].group(1)
    main_start_line = content[:scripts[-1].start()].count('\n') + 1
    print(f"Main script starts at line: {main_start_line}")
    
    # Look for all let/const declarations in the main script
    for m in re.finditer(r'\b(let|const)\s+(\w+)', main_script):
        line_no = main_start_line + main_script[:m.start()].count('\n')
        sys.stdout.buffer.write(f"Line {line_no}: {m.group(0)}\n".encode('utf-8'))
