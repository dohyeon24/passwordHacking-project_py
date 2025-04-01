import subprocess  # subprocess 모듈을 사용하여 외부 명령어를 실행

# 파일 경로 설정 (분석할 실행 파일의 경로)
file_path = r"C:\Users\김도현\Desktop\passwordHacking.exe"

# 1. strings 명령어를 사용하여 실행 파일에서 문자열 추출
def extract_strings(file_path):
    try:
        # 'strings' 명령어를 실행하여 실행 파일에서 텍스트를 추출
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        return result.stdout.split("\n")
    except Exception as e:
        # 오류가 발생한 경우 오류 메시지를 리스트로 반환
        return [f"Error: {str(e)}"]

# 2. objdump 명령어를 사용하여 실행 파일의 어셈블리 코드 분석
def disassemble_file(file_path):
    try:
        # 'objdump' 명령어를 실행하여 실행 파일을 어셈블리 코드로 변환
        result = subprocess.run(["objdump", "-d", file_path], capture_output=True, text=True)
        return result.stdout.split("\n")
    except Exception as e:
        # 오류가 발생한 경우 오류 메시지를 리스트로 반환
        return [f"Error: {str(e)}"]

# 3. cmp 명령어가 포함된 부분 찾기
def find_cmp_in_disassembly(disassembled_code):
    cmp_lines = [line for line in disassembled_code if "cmp" in line]
    return cmp_lines

# 실행 파일에서 문자열 추출
strings = extract_strings(file_path)  # 'strings' 명령어로 텍스트 추출

# 실행 파일 역어셈블
disassembled_code = disassemble_file(file_path)  # 'objdump' 명령어로 어셈블리 코드 분석

# cmp 명령어 분석
cmp_lines = find_cmp_in_disassembly(disassembled_code)  # 'cmp' 명령어가 있는 라인 찾기

# cmp 명령어가 포함된 코드 출력
print("\n[cmp 명령어가 포함된 부분]")
# 찾은 'cmp' 명령어가 포함된 각 라인을 출력
for line in cmp_lines:
    print(line)

# 비밀번호 발견 0x4E55741 (16진수)
password_hex = 0x4E55741  # 16진수 값
password_decimal = int(password_hex)  # 16진수를 10진수로 변환

# 예상 비밀번호 출력
print(f"\n[16진수 비밀번호는: {hex(password_hex)} (16진수)]")  # 16진수로도 출력
print(f"[예상 비밀번호는: {password_decimal} (10진수)]")

