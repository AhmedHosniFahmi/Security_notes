from pwn import *
from Crypto.Util.number import *
from Crypto.Hash import SHA256
import base64, hashlib, os, gmpy2, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

print(long_to_bytes(36880882204128738400791013448930507483575569461345866246648979168929576190163201812893707600076617085))
print(long_to_bytes(int("c86da0de759f607f2a090869bd94a2d8", base=16)))

print(hex(bytes_to_long(b"$6$OPPu8.AR6Nhje.Jt$2qck9KUQVuCtbRucXeyfSZ61KWDlRvsYJQZQgkdbR6yXjpxMe5mMQMZWr815zTWnFTjre1rD3Tnlth7ZWyIPN/")))



# p = 16007670376277647657
# B = 11289939170989149892
# A = 12356772468286421022
# g = 2
# iv = "98a407cf35831bdeb3a73e6dac637c28"
# encrypted_flag = "d85826570d00e83c4e309a36aca89e4f20982610a471247fc5816f6f95ce3cbdc5d10339901aebdc8ffe87efc4bd8dd0cc1c3f68890f30b7568041943d8411c923de05ba11562a80463cd435430edc66"
# max_number = 2 ** 512 - 1
# print(len("9"*20))


# def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
#     # Derive AES key from shared secret
#     sha1 = hashlib.sha1()
#     sha1.update(str(shared_secret).encode('ascii'))
#     key = sha1.digest()[:16]
#     # Decrypt flag
#     ciphertext = bytes.fromhex(ciphertext)
#     iv = bytes.fromhex(iv)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = cipher.decrypt(ciphertext)
#     print(plaintext.decode())

# shared_secret = int("8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0",base=16)
# decrypt_flag(shared_secret,iv,encrypted_flag)









# print(long_to_bytes(44981230718212183604274785925793145442655465025264554046028251311164494127485))
# def remove_0x_0x0_from_json(j):
#     for key,value in j.items():
#         if value[0:2] == "0x":j[key] = value[2:]
#         if value[0:3] == "0x0":j[key] = value[3:]

# connection = remote("socket.cryptohack.org",13371)

# intercept_alice = json.loads(connection.recvuntil(b"}").decode()[len("Intercepted from Alice: "):]);connection.recvuntil(b"Send to Bob:")
# remove_0x_0x0_from_json(intercept_alice)
# for i in intercept_alice.keys() :print (i)
# connection.send(json.dumps(intercept_alice).encode())

# # connection.send(json.dumps({"p":intercept_alice['p'], "g":intercept_alice['g'], "A":intercept_alice['A']}).encode())

# intercept_bob = json.loads(connection.recvuntil(b"}").decode()[len("Intercepted from Bob: "):]);connection.recvuntil(b"Send to Alice:")
# remove_0x_0x0_from_json(intercept_bob)
# for i in intercept_bob.keys() :print (i)

# connection.send(json.dumps({'B': intercept_alice['g']}).encode())
# iv_falg = json.loads(connection.recvuntil(b"}").decode()[len("Intercepted from Alice: "):])
# print(iv_falg)






# g = 2
# p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
# A = 112218739139542908880564359534373424013016249772931962692237907571990334483528877513809272625610512061159061737608547288558662879685086684299624481742865016924065000555267977830144740364467977206555914781236397216033805882207640219686011643468275165718132888489024688846101943642459655423609111976363316080620471928236879737944217503462265615774774318986375878440978819238346077908864116156831874695817477772477121232820827728424890845769152726027520772901423784
# b = 197395083814907028991785772714920885908249341925650951555219049411298436217190605190824934787336279228785809783531814507661385111220639329358048196339626065676869119737979175531770768861808581110311903548567424039264485661330995221907803300824165469977099494284722831845653985392791480264712091293580274947132480402319812110462641143884577706335859190668240694680261160210609506891842793868297672619625924001403035676872189455767944077542198064499486164431451944
# js = {'iv': '737561146ff8194f45290f5766ed6aba', 'encrypted_flag': '39c99bf2f0c14678d6a5416faef954b5893c316fc3c48622ba1fd6a9fe85f3dc72'}

# shared = pow(A, b, p)

# def is_pkcs7_padded(message):
#     padding = message[-message[-1]:]
#     return all(padding[i] == len(padding) for i in range(0, len(padding)))


# def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
#     # Derive AES key from shared secret
#     sha1 = hashlib.sha1()
#     sha1.update(str(shared_secret).encode('ascii'))
#     key = sha1.digest()[:16]
#     # Decrypt flag
#     ciphertext = bytes.fromhex(ciphertext)
#     iv = bytes.fromhex(iv)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = cipher.decrypt(ciphertext)

#     if is_pkcs7_padded(plaintext):
#         return unpad(plaintext, 16).decode('ascii')
#     else:
#         return plaintext.decode('ascii')
    
# print(decrypt_flag(shared, js['iv'], js['encrypted_flag']))


# def encrypt_flag(shared_secret: int):
#     # Derive AES key from shared secret
#     sha1 = hashlib.sha1()
#     sha1.update(str(shared_secret).encode('ascii'))
#     key = sha1.digest()[:16]
#     # Encrypt flag
#     iv = os.urandom(16)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     ciphertext = cipher.encrypt(pad(FLAG, 16))
#     # Prepare data to send
#     data = {}
#     data['iv'] = iv.hex()
#     data['encrypted_flag'] = ciphertext.hex()
#     return data


# print(encrypt_flag(shared))






# SHA256.new().digest()
# plain = b"crypto{Immut4ble_m3ssag1ng}"
# hash = bytes_to_long(hashlib.sha256(plain).digest())
# c = hash
# d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689
# n = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
# print(pow(c,d,n))

# resd = [i for i in ints if pow(i, (p-1)//2, p) == 1]
# print(resd)

# for n in ints:
#   if pow(n, p >> 1, p) == 1:  # direct bitshift because every prime (except 2) is odd
#     print("quadratic residue:", n)
#     print("\nroot:", pow(n, (p+1) >> 2, p))
#     break

# def gcd(n1: int, n2: int)-> int:
#     if n2 > n1:
#         n1,n2 = n2,n1
#     if n1%n2 == 0:
#         return n2
#     else:
#        return gcd(n2, n1-n2*int(n1/n2))
    
# print(gcd(46867, 23173))

# def egcd(a, b):
#     x,y, u,v = 0,1, 1,0
#     while a != 0:
#         q, r = b//a, b%a
#         m, n = x-u*q, y-v*q
#         b,a, x,y, u,v = a,r, u,v, m,n
#     gcd = b
#     return gcd, x, y


# print (egcd(26513,32321))

# cipher = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")[0:7]+bytes.fromhex("04")
# print(xor(cipher, b"crypto{}"))
# cipher = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
# print(xor(cipher, b'myXORkey'))
# print('bytes'.encode())


# k1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
# k2 = xor(k1, bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"))
# k3 = xor(k2, bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"))
# flag = xor(k1, k2, k3, bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"))
# print(flag)

# cipher = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")
# for i in range(0, 224):
#     if xor(i, cipher)[0:6] in b"crypto{}":
#         print(xor(i, cipher))
#         print(i)
#         break