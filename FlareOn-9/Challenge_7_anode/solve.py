import re
import math
from z3 import *


TARGET = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76]


def get_rand():
    global math_random, math_random_offset
    rand = math_random[math_random_offset]
    math_random_offset += 1
    return rand


# Get values returned by Math.random()
# Those values were retrieved by patching the JS script
math_random = []
math_random_offset = 0
with open("math_random.txt", "r") as f:
    for line in f.readlines():
        math_random.append(float(line.strip()))

# Get if(cond) boolean value
# Those values were retrieved by patching the JS script
conditions = dict()
with open("if_cond_results.txt", "r") as f:
    for line in f.readlines():
        cond, val = line.strip().split(':')
        conditions[cond] = int(val)

# Read JS script
with open("anode.js", "r") as f:
    js_script = f.read()

# For each state, get equations
equations_cleaned = []
next_state = 1337
while True:
    # compute current state value
    cur_state = math.floor(get_rand() * (2**30)) ^ next_state

    # break when state equal to stop value
    if cur_state == 185078700:
        break

    # get offset of corresponding switch case in js script
    m = re.search(f'case {cur_state}:', js_script)
    start, end = m.span()

    # check if there is a call to Math.random()
    branch_is_taken = False
    if js_script[end+9:end+33] == "if (Math.random() < 0.5)":
        if get_rand() < 0.5:
            branch_is_taken = True
    # if(cond) 
    else:
        # get cond value using regex
        cond = re.search(r'if \(([0-9n]+)\)', js_script[end+9:end+30])
        cond_val = cond.groups()[0]
        if conditions[cond_val]:
            branch_is_taken = True

    # get equation after in if branch
    if branch_is_taken:
        equations = re.findall(r'b\[[0-9]+\] .= [a-zA-Z\.\*0-9\+;= &\(\)\[\]]*\n', js_script[end:end+150])
    else:
        # get else offset and get equation from there
        m_else = re.search('else {', js_script[end:end+300])
        start_else, end_else = m_else.span()
        equations = re.findall(r'b\[[0-9]+\] .= [a-zA-Z\.\*0-9\+;= &\(\)\[\]]*\n', js_script[end+end_else:end+end_else+150])

    # clean equations
    for eq in equations:
        eq_cleaned = eq.strip()

        # if there is a call to Math.random() -> replace with actual value
        if "Math.floor(Math.random() * 256)" in eq_cleaned:
            eq_cleaned = eq_cleaned.replace("Math.floor(Math.random() * 256)", str(math.floor(get_rand() * 256)))

        if re.match(r'b\[[0-9]+\] &= 0xFF;', eq_cleaned):
            continue

        equations_cleaned.append(eq_cleaned.rstrip(';'))

    # search for next state value
    res = re.search(r'state = ([0-9]+);\n', js_script[end:end+500])
    next_state = int(res.groups()[0])


# Iterate over equations to get final equations with fixed variables names
versions = dict()

for i in range(44):
    versions[i] = 0

final_equations = []
for eq in equations_cleaned:
    m_idx = re.search(r'b\[([0-9]+)\] .=', eq)
    m_idx_val = int(m_idx.groups()[0])

    new_eq = eq
    for idx in re.findall(r'b\[([0-9]+)\]', eq):
        new_eq = re.sub(f"b\[{idx}\]", f"b_{idx}_{versions[int(idx)]}", new_eq)

    new_eq = new_eq.split("=")
    
    versions[m_idx_val] += 1
    
    final_eq = f"({new_eq[0]} ({new_eq[1]})) == b_{m_idx_val}_{versions[int(m_idx_val)]}"
    final_eq = final_eq.replace("& 0xFF", "")
    final_equations.append(final_eq)


s = Solver()

# create Z3 variables
for i in range(44):
    for j in range(versions[i]+1):
        var = f"b_{i}_{j}"
        exec(f"{var} = BitVec('{var}', 8)")

# add equations
for eq in final_equations:
    s.add(eval(eq))

# add constraints on target
for i in range(44):
    var = f"b_{i}_{versions[i]}"
    s.add(TARGET[i] == eval(var))

for i in range(44):
    s.add(eval(f"b_{i}_0 < 127"))


# solve
if s.check() == sat:
    m = s.model()

    flag = []
    for i in range(44):
        flag.append(m[eval(f"b_{i}_0")].as_long())
    print(bytes(flag).decode())
