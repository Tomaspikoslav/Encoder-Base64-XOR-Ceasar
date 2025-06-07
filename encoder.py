import base64 as bs
import ansi_color as ac
import string as st
import os

###T.M###

##############################BASE-64#####################################

def encode_base64():
    encostr = input(f"{ac.blu}Text to encode: {ac.res}")
    encoasci = encostr.encode("ascii")
    bs64 = bs.b64encode(encoasci)
    bs64str = bs64.decode("ascii")
    print(f"{ac.gre}Encoded text: {bs64str}{ac.res}")


def decode_base64():
    decostr = input(f"{ac.gre}Text to decode: {ac.res}")
    decoasci = decostr.encode("ascii")
    decod = bs.b64decode(decoasci)
    decodstr = decod.decode("ascii")
    print(f"{ac.blu}Decoded text: {decodstr}{ac.res}")


##############################CEASAR-CYPHER################################

def shift_text(text, shift):
    alpha = st.ascii_lowercase
    sht = ""
    for char in text:
        if char in alpha:
            nindex = (alpha.index(char) + shift) % 26
            sht += alpha[nindex]
        else:
            sht += char
    return sht

def ceasar_cypher():
    dist = int(input(f"{ac.cya}Distance: {ac.res}"))
    distcal = (0-dist)
    csrstr = input(f"{ac.blu}Text: {ac.res}")
    csrenc = shift_text(csrstr.lower(), dist)
    csrdec = shift_text(csrstr.lower(), distcal)
    print(f"{ac.gre}Encoded text: {csrenc}{ac.res}")
    print(f"{ac.yel}Decoded text: {csrdec}{ac.res}")

def brute_force_ceasar_cypher():
    brtstr = input(f"{ac.blu}Text to bruteforce: {ac.res}")
    curstg = -27
    for i in range(55):
        curstr = shift_text(brtstr.lower(), curstg)
        print(f"{ac.gre}Bruteforce try {curstg}: {ac.res}{curstr}")
        print("")
        curstg += 1
        tm.sleep(0.3)
    print(f"{ac.yel}Bruteforce ended{ac.res}")

################################XOR-CYPHER####################################
def XOR_cypher(inpString, operation_name):
    xorKey = input(f"{ac.cya}XOR key for {operation_name}: {ac.res}")
    if not xorKey:
        print(f"{ac.red}Error: XOR key cannot be empty!{ac.res}")
        return None
    xorKey_char = xorKey[0]

    result = []
    for char in inpString:
        result_char = chr(ord(char) ^ ord(xorKey_char))
        result.append(result_char)
    return ''.join(result)

def XOR_encode():
    xorstr = input(f"{ac.blu}Text to encode: {ac.res}")
    xorenc = XOR_cypher(xorstr, "encoding")
    print(f"{ac.gre}Encoded String: {xorenc}{ac.res}")

def XOR_decode():
    xorstr2 = input(f"{ac.gre}Text to decode: {ac.res}")
    xordec = XOR_cypher(xorstr2, "decoding")
    print(f"{ac.blu}Decoded text: {xordec}{ac.res}")

################################MENU-MENU#####################################

def service_error():
    print(f"{ac.red} Error : only input number of the service required {ac.res}")
    menu()

def menu():
    print(f"{ac.mag}CRYPTOGRAPHY{ac.res}")
    print("\n")
    print(f"{ac.gre}1) Base64 {ac.res}")
    print(f"{ac.blu}2) XOR {ac.res}")
    print(f"{ac.yel}3) Ceasar {ac.res}")
    print("")
    menu_chooser()

def menu_chooser():
    opt = int(input(f"{ac.cya}Service: {ac.res}"))
    if opt == 1:
        os.system("cls")
        Base64_chooser()
        menu()
    elif opt == 2:
        os.system("cls")
        Xor_chooser()
        menu()
    elif opt == 3:
        os.system("cls")
        Ceasar_chooser()
        menu()
    else:
        service_error()


def Base64_chooser():
    print(f"{ac.gre}BASE-64{ac.res}")
    print(f"{ac.gre}  1)Encode{ac.res}")
    print(f"{ac.blu}  2)Decode{ac.res}")
    print(f"{ac.yel}  3)Go back{ac.res}")
    print("")
    bsopt = int(input(f"{ac.cya}Service: {ac.res}"))
    if bsopt == 1:
        os.system("cls")
        encode_base64()
        menu()
    elif bsopt == 2:
        os.system("cls")
        decode_base64()
        menu()
    elif bsopt == 3:
        os.system("cls")
        menu()
    else:
        service_error()

def Xor_chooser():
    print(f"{ac.blu}XOR{ac.res}")
    print(f"{ac.gre}  1)Encode{ac.res}")
    print(f"{ac.blu}  2)Decode{ac.res}")
    print(f"{ac.yel}  3)Go back{ac.res}")
    print("")
    bsopt = int(input(f"{ac.cya}Service: {ac.res}"))
    if bsopt == 1:
        os.system("cls")
        XOR_encode()
    elif bsopt == 2:
        os.system("cls")
        XOR_decode()
    elif bsopt == 3:
        os.system("cls")
        menu()
    else:
        service_error()

def Ceasar_chooser():
    print(f"{ac.yel}Ceasar-Cypher{ac.res}")
    print(f"{ac.gre}  1)Move Letters{ac.res}")
    print(f"{ac.mag}  2)Bruteforce{ac.res}")
    print(f"{ac.yel}  3)Go back{ac.res}")
    print("")
    bsopt = int(input(f"{ac.cya}Service: {ac.res}"))
    if bsopt == 1:
        os.system("cls")
        ceasar_cypher()
    elif bsopt == 2:
        os.system("cls")
        brute_force_ceasar_cypher()
    elif bsopt == 3:
        os.system("cls")
        menu()
    else:
        service_error()

menu()
