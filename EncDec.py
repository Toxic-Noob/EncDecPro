import sys
import base64 
import hashlib
import subprocess as s
import subprocess
import os, sys, time
import urllib.parse
from modules.decode import *
from modules.encode import *
from modules.secret_msg import *
from modules.hash_dec import *
from modules.update import *
import requests
#import subprocess as sb


def psb(z):
    for i in z + "\n":
        sys.stdout.write(i)
        sys.stdout.flush()
        time.sleep(0.03)

def oppsb(z):
    for i in z + "\n":
        sys.stdout.write(i)
        sys.stdout.flush()
        time.sleep(0.01)

def logopsb(z):
    for i in z + "\n":
        sys.stdout.write(i)
        sys.stdout.flush()
        time.sleep(0.0003)


def iserror(func, *args, **kw):
    try:
        func(*args, **kw)
        return False
    except Exception:
        return True

def logo():
    print("\033[92m")
    os.system("clear")
    logopsb(" _____            ____              ____            \n| ____|_ __   ___|  _ \  ___  ___  |  _ \ _ __V1.0  \n|  _| | '_ \ / __| | | |/ _ \/ __| | |_) | '__/ _ \ \n| |___| | | | (__| |_| |  __/ (__  |  __/| | | (_) |\n|_____|_| |_|\___|____/ \___|\___| |_|   |_|  \___/ \n                                                    \n")
    logopsb("\033[3;90m                            A Product Of ToxicNoob\033[0;92m")
    time.sleep(0.6)
    logopsb("\033[34m\n|****************************************************|\n|\033[3m Author   : ToxicNoob                               \033[0;34m|\n|\033[3m Tool     : Encrypt Decryptor Pro                   \033[0;34m|\n|\033[3m Version  : 1.1                                     \033[0;34m|\n|\033[3m Link     : https://www.github.com/Toxic-Noob/	     \033[0;34m|\n|\033[3m Coded By : HunterSl4d3      		     	     \033[0;34m|\n******************************************************")
    print("\033[92m")
    time.sleep(0.6)


def logout():
    psb("\n    \033[92m[*] Thanks For Using Our Tool 💞💞")
    psb("    [*] Visit Our GitHub For More Tools....")
    os.system("xdg-open https://github.com/Toxic-Noob/")
    psb("\n    \033[33m[\033[92m   https://github.com/Toxic-Noob/   \033[33m]\033[37;40;0m\n")
    sys.exit()

def supports():
    logo()
    psb("\033[92m\n    [*] Supported Encryptions :")
    time.sleep(0.5)
    psb("\n    [*] Base64")
    psb("    [*] Base32")
    psb("    [*] Base16")
    psb("    [*] Hex")
    psb("    [*] Binary")
    psb("    [*] CHR")
    psb("    [*] Hash")
    psb("    [*] Morse")
    psb("    [*] URLEncode")
    psb("    [*] Rot13")
    time.sleep(0.7)
    psb("\n    [*] If You Have Any Encryption Suggestions, Please Contact US...")
    psb("\n    [ Via Email ] : ToxicNoob.Sl4d3.Official@gmail.com")
    

def manual():
    logo()
    psb("\033[92m\n    [*] All The Encryptions, Except Hash and Rot13 Can Be Detected Autometically!!")
    psb("\n    [*] If You Cann't Find Your Expected Data, Try Decrypting Your String With Hash and Rot13 From [*] Custom Decode Option...")
    time.sleep(0.5)
    psb("\n    [*] About Secret Massage Option:")
    psb("\n    [*] Secret Massage Option Is For Encrypting Your Massages...")
    psb("    [*] No One Except, Who Knowes The Secret Code Of Decryption, Can Read Your Massage..")
    time.sleep(0.5)
    psb("\n    [*] Thanks For Using Our Tool 💞💞")

def decode(input_data):
    try:
                                        #Morse
                                        dec_data = morse_dec(input_data)
                                        return dec_data
    except:
        try:
            #Hex
            if("0x" in input_data):
                dec_data = hex_dec(input_data)
                return dec_data
            else:
                raise ValueError
        except:
            try:
                #Binary
                dec_data = bin1_dec(input_data)
                return dec_data
            except:
                try:
                    #CHR
                    if("chr" in input_data):
                        dec_data = chr_dec(input_data)
                        return dec_data
                        sec = dec_data
                    else:
                        raise ValueError
                except:
                    try:
                        #URLEncode
                        if not ("%" in input_data):
                            raise ValueError
                        dec_data = url_dec(input_data)
                        return dec_data
                    except:
                        try:
                            #Binary2
                            dec_data = bin2_dec(input_data)
                            return dec_data
                        except:
                            try:
                                #Base32
                                dec_data = b32_dec(input_data)
                                return dec_data
                            except:
                                try:
                                    #Base16
                                    if set(input_data).issubset({'0', '1'}) and bool(input_data) or set(input_data).issubset({'0', '1', ' '}) and bool(input_data):
                                        raise ValueError
                                    dec_data = b16_dec(input_data)
                                    return dec_data
                                except:
                                    try:
                                        #Base64
                                        dec_data = b64_dec(input_data)
                                        return dec_data
                                    except Exception as e:
                                        return None


def encode(input_data):
    base64_data = b64_enc(input_data)
    base32_data = b32_enc(input_data)
    base16_data = b16_enc(input_data)
    hex_data = "0x"+hex_enc(input_data)
    bin_data = bin_enc(input_data)
    chr_data = chr_enc(input_data)
    hash_data = hash_enc(input_data)
    try:
        morse_data = morse_enc(input_data)
    except:
        pass
    url_data = url_enc(input_data)
    rot13_data = rot13(input_data)
    logo()
    psb("\n\033[92m[*] Encrypted Data :")
    print("\n\033[31m[\033[34m Base64 \033[31m]\033[33m : \033[37m"+base64_data)
    print("\n\033[31m[\033[34m Base32 \033[31m]\033[33m : \033[37m"+base32_data)
    print("\n\033[31m[\033[34m Base16 \033[31m]\033[33m : \033[37m"+base16_data)
    print("\n\033[31m[\033[34m  Hex   \033[31m]\033[33m : \033[37m"+hex_data)
    print("\n\033[31m[\033[34m Binary \033[31m]\033[33m : \033[37m"+bin_data)
    print("\n\033[31m[\033[34m  CHR   \033[31m]\033[33m : \033[37m"+chr_data)
    print("\n\033[31m[\033[34m  Hash  \033[31m]\033[33m : \033[37m"+hash_data)
    try:
        print("\n\033[31m[\033[34m Morse  \033[31m]\033[33m : \033[37m"+morse_data)
    except:
        pass
    print("\n\033[31m[\033[34m URLEnc \033[31m]\033[33m : \033[37m"+url_data)
    print("\n\033[31m[\033[34m Rot13  \033[31m]\033[33m : \033[37m"+rot13_data)


def custom_enc():
    logo()
    print("\n\033[92m[*] Choose The Formate You Want To Encode Your String To..")
    print("\n    [01] Base64")
    print("    [02] Base32")
    print("    [03] Base16")
    print("    [04] Hex")
    print("    [05] Binary")
    print("    [06] CHR")
    print("    [07] Hash")
    print("    [08] Morse")
    print("    [09] URLEncode")
    print("    [10] Rot13")
    print("    [##] Exit")
    ipt = input("\n    [*] Enter Your Choice:> \033[37m")
    if not (ipt=="10"):
        ipt = ipt.replace("0", "").replace("##", "#")
    while not ipt in ["1", "2", "3", "4" ,"5" ,"6", "7", "8", "9", "10", "#"]:
        psb("\n\033[91m    [!] Choose a Correct Option!!\033[92m")
        time.sleep(0.8)
        ipt = input("\n    [*] Enter Your Choice:> \033[37m")
        if not (ipt=="10"):
            ipt = ipt.replace("0", "").replace("##", "#")
    if (ipt=="1"):
        enc_data = (b64_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="2"):
        enc_data = (b32_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="3"):
        enc_data = (b16_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="4"):
        enc_data = (hex_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="5"):
        enc_data = (bin_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="6"):
        enc_data = (chr_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="7"):
        enc_data = (hash_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="8"):
        enc_data = (morse_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="9"):
        enc_data = (url_enc(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="10"):
        enc_data = (rot13(in_data()))
        print("\033[92m\n    [*] Encrypted Data:> \033[37m"+enc_data)
    elif (ipt=="#"):
        pass

def custom_dec():
    logo()
    print("\033[92m\n[*] Choose The Formate You Want To Decode Your String From...")
    print("\n    [01] Base64")
    print("    [02] Base32")
    print("    [03] Base16")
    print("    [04] Hex")
    print("    [05] Binary")
    print("    [06] CHR")
    print("    [07] Hash")
    print("    [08] Morse")
    print("    [09] URLEncode")
    print("    [10] Rot13")
    print("    [##] Exit")
    ipt = input("\n    [*] Enter Your Choice:> \033[37m")
    if not (ipt=="10"):
        ipt = ipt.replace("0", "").replace("##", "#")
    while not ipt in ["1", "2", "3", "4" ,"5" ,"6", "7", "8", "9", "10", "#"]:
        psb("\n\033[91m    [!] Choose a Correct Option!!\033[92m")
        time.sleep(0.8)
        ipt = input("\n    [*] Enter Your Choice:> \033[37m")
        if not (ipt=="10"):
            ipt = ipt.replace("0", "").replace("##", "#")
    if (ipt=="1"):
        inp_data = in_data()
        while iserror(b64_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Base64 Encoded..!!")
            inp_data = in_data()
        dec_data = (b64_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="2"):
        inp_data = in_data()
        while iserror(b32_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Base32 Encoded..!!")
            inp_data = in_data()
        dec_data = (b32_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="3"):
        inp_data = in_data()
        while iserror(b16_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Base16 Encoded..!!")
            inp_data = in_data()
        dec_data = (b16_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="4"):
        inp_data = in_data()
        while iserror(hex_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Hex Encoded..!!")
            inp_data = in_data()
        dec_data = (hex_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="5"):
        inp_data = in_data()
        while iserror(bin1_dec, inp_data) == True and iserror(bin2_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Binary Encoded..!!")
            inp_data = in_data()
        try:
            dec_data = (bin1_dec(inp_data))
        except:
            dec_data = (bin2_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="6"):
        inp_data = in_data()
        while iserror(chr_dec, inp_data) == True or ("NameError" in chr_dec(inp_data)):
            psb("\n\033[91m    [!] Your String Is Not CHR Encoded..!!")
            inp_data = in_data()
        dec_data = (chr_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="7"):
        dec_data = (hash_dec(in_data()))
        while (dec_data == "inv"):
            dec_data = (hash_dec(in_data()))
        if not (dec_data == None) and not (dec_data == "inv") and not (dec_data == "None"):
            print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
        elif (dec_data == "inv"):
            pass
        else:
            psb("\033[91m\n    [*] Couldn't Decrypt Hash String..")
            psb("    [*] You Can Use Online Tool To Decrypt Your Hash String...")
            os.system("xdg-open https://hashes.com")
    elif (ipt=="8"):
        inp_data = in_data()
        while iserror(morse_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not Morse Encoded..!!")
            inp_data = in_data()
        dec_data = (morse_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="9"):
        inp_data = in_data()
        while iserror(url_dec, inp_data) == True:
            psb("\n\033[91m    [!] Your String Is Not URL Encoded..!!")
            inp_data = in_data()
        dec_data = (url_dec(inp_data))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="10"):
        dec_data = (rot13(in_data()))
        print("\033[92m\n    [*] Decrypted Data:> \033[37m"+dec_data)
    elif (ipt=="#"):
        pass

def sec_msg():
    logo()
    print("\033[92m\n    [01] Encode Massage")
    print("    [02] Decode Massage")
    print("    [##] Exit")
    igp = input("\n    [*] Enter Your Choice:> \033[37m").replace("0", "").replace("##", "#")
    while not igp in ["1", "2", "#"]:
        psb("\n\033[91m    [!] Enter a Correct Choice!!\033[92m")
        igp = input("\n    [*] Enter Your Choice:> \033[37m").replace("0", "")
    if (igp == "1"):
        msg = input("\033[92m\n    [*] Enter Your Massage:> \033[37m")
        code = input("\033[92m\n    [*] Enter Your Decrypt Code:> \033[37m")
        enc_msg = sec_msg_enc(msg, code)
        print("\033[92m\n    [*] Your Secret Massage Is : \033[37m"+enc_msg)
    elif (igp == "2"):
        msg = input("\033[92m\n    [*] Enter Your Secret Massage:> \033[37m")
        code = input("\033[92m\n    [*] Enter Your Decrypt Code:> \033[37m")
        dec_msg = sec_msg_dec(msg, code)
        print("\033[92m\n    [*] Your Secret Massage Is : \033[37m"+dec_msg)
    elif (igp == "3"):
        pass


def options():
    oppsb("\033[92m\n    [*] Choose Your Option...")
    time.sleep(0.5)
    print("\n    [01] Simple Decode")
    print("    [02] Simple Encode")
    print("    [03] Custom Decode")
    print("    [04] Custom Encode")
    print("    [05] Secret Massage")
    print("    [06] Tool's Manual")
    print("    [07] Supported Encryptions")
    print("    [08] Update Tool")
    print("    [##] Exit")
    ip = input("\n    [*] Enter Your Choice:> \033[37m").replace("0", "").replace("##", "#")
    while not ip in ["1", "2", "3", "4", "5", "6", "7", "8", "#"]:
        psb("\n\033[91m    [!] Enter a Correct Choice!!\033[92m")
        ip = input("\n    [*] Enter Your Choice:> \033[37m").replace("0", "").replace("##", "#")
    if (ip=="1"):
        while True:
            inp_data = in_data_altr()
            if (inp_data == None):
                break
            data = decode(inp_data)
            if not (data == None):
                print("\033[92m\n    [*] Your Decrypted Data Is : \033[37m"+data)
            else:
                print("\n    \033[91m[!] No Encryption Found!!\033[92m")
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "2"):
        while True:
            inp_data = in_data_altr()
            if (inp_data == None):
                break
            encode(inp_data)
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "3"):
        custom_dec()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "4"):
        custom_enc()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "5"):
        sec_msg()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "6"):
        manual()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "7"):
        supports()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "8"):
        logo()
        update()
        p = input("\n\033[92m    [*] Press Enter To Go Back To Main Menu...")
    elif (ip == "#"):
        logout()

def in_data():
    string = input("\033[92m\n    [*] Enter your String:> \033[37m")
    while (string == ""):
        psb("\n\033[91m    [*] You Must Enter Some String...")
        string = input("\033[92m\n    [*] Enter your String:> \033[37m")
    return string


def in_data_altr():
    string = input("\033[92m\n    [*] Enter your String:> \033[37m")
    if not (string == ""):
        return string


if __name__ == "__main__":
    while True:
        logo()
        options()
