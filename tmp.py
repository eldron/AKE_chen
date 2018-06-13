import socket
import sys
import six
from charm.toolbox.integergroup import IntegerGroup
from charm.core.math.integer import *
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import *
from sha2 import Waters
from MYPRF import MYPRF

from length_functions import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to party B
server_address = ('localhost', 10000)



# long-term key generation, session execution, then session key output

# length of group elements, may change this later
# generate the group G
bits = 1024
group = IntegerGroup()
group.paramgen(bits)
group_order = group.q
#print('group order is ', group_order)
print('group.p = ', group.p)
print('group.q = ', group.q)

group_p_bytes = Conversion.IP2OS(group.p, 128)
group_q_bytes = Conversion.IP2OS(group.q, 128)


alpha_1_value = randomBits(160) % group_order
alpha_2_value = randomBits(160) % group_order
beta_1_value = randomBits(160) % group_order
beta_2_value = randomBits(160) % group_order
alpha_1_bytes = Conversion.IP2OS(alpha_1_value, 20)
alpha_2_bytes = Conversion.IP2OS(alpha_2_value, 20)
beta_1_bytes = Conversion.IP2OS(beta_1_value, 20)
beta_2_bytes = Conversion.IP2OS(beta_2_value, 20)

# two random generators of group G
g_1 = group.randomGen()
g_2 = group.randomGen()
g = group.randomGen()
g_1_bytes = Conversion.IP2OS(g_1, 128)
g_2_bytes = Conversion.IP2OS(g_2, 128)
g_bytes = Conversion.IP2OS(g, 128)

tmp1 = (g_1 ** alpha_1_value) % group.p
tmp2 = (g_2 ** alpha_2_value) % group.p
hp_1 = (tmp1 * tmp2) % group.p
tmp1 = (g_1 ** beta_1_value) % group.p
tmp2 = (g_2 ** beta_2_value) % group.p
hp_2 = (tmp1 * tmp2) % group.p
hp = {'hp_1':hp_1, 'hp_2':hp_2}
hp_1_bytes = Conversion.IP2OS(hp_1, 128)
hp_2_bytes = Conversion.IP2OS(hp_2, 128)

# generate r_1, r_2, t
# currently set t_1(k) to 192 bits, t_2(k) to 640 bits, u(k) to 192 bits, t_3(k) to 160 bits
# t_1(k) and u(k) are calculated from the length of r and x
r_1_value = randomBits(192)
r_2_value = randomBits(640)
r_1_bytes = Conversion.IP2OS(r_1_value, 24)
r_2_bytes = Conversion.IP2OS(r_2_value, 80)
t_value = randomBits(160)
t_bytes = Conversion.IP2OS(t_value, 20)

# session execution
e_value = randomBits(192)
e_bytes = Conversion.IP2OS(e_value, 24)
# set l_1, l_2 (length of the output of extractor 1 and extractor 2) to be 128 bits, the length of AES key
	
# hash alpha_1_bytes, alpha_2_bytes, beta_1_bytes, beta_2_bytes, r_1_bytes together to get lsk_A_prime
tmp = alpha_1_bytes + alpha_2_bytes + beta_1_bytes + beta_2_bytes + r_1_bytes
group_for_hash = PairingGroup("SS512")
waters = Waters(group_for_hash)
lsk_A_prime = waters.sha2(tmp)
lsk_A_prime = lsk_A_prime[0:16] # get the first 128 bits
	
# hash e_bytes, r_2_bytes together to get esk_A_prime
tmp = e_bytes + r_2_bytes
esk_A_prime = waters.sha2(tmp)
esk_A_prime = esk_A_prime[0:16] # get the first 128 bits

# calculate r and x
prf1 = MYPRF(lsk_A_prime)
tmp1 = prf1._encrypt(e_bytes)
prf2 = MYPRF(esk_A_prime)
tmp2 = prf2._encrypt(r_1_bytes)
tmp1 = tmp1['CipherText']
tmp2 = tmp2['CipherText']
r_value = Conversion.OS2IP(tmp1[0:20], True) + Conversion.OS2IP(tmp2[0:20], True)
x_value = Conversion.OS2IP(tmp1[20:40], True) + Conversion.OS2IP(tmp2[20:40], True)
r_value = r_value % group_order
x_value = x_value % group_order

u_1_value = (g_1 ** r_value) % group.p
u_2_value = (g_2 ** r_value) % group.p
X_value = (g ** x_value) % group.p
# send group.p, group.q, g, g1, g2, hp1, hp2, u1, u2, X, t to party B
u_1_bytes = Conversion.IP2OS(u_1_value, 128)
u_2_bytes = Conversion.IP2OS(u_2_value, 128)
X_bytes = Conversion.IP2OS(X_value, 128)
to_send = group_p_bytes + group_q_bytes + g_bytes + g_1_bytes + g_2_bytes + hp_1_bytes + hp_2_bytes + u_1_bytes + u_2_bytes + X_bytes + t_bytes
	
# print('connecting to {} port {}'.format(*server_address))
# sock.connect(server_address)
# sock.sendall(to_send)
# print('data sent')

# # receive from party B
# amount_expected = len(hp_1_bytes + hp_2_bytes + u_1_bytes + u_2_bytes + X_bytes + t_bytes)
# data_received = b''
# while len(data_received) < amount_expected:
# 	data_received += sock.recv(amount_expected)

# if(len(data_received) != amount_expected):
# 	print('length of data received from party B is not correct!!!')

# hash data sent and received together to get d, length of d is 160 bits
#d_bytes = waters.sha2(to_send + data_received)
d_bytes = waters.sha2(to_send)
d_bytes = d_bytes[0:20]
# hp_1_prime_bytes = data_received[0:128]
# hp_2_prime_bytes = data_received[128: 128 * 2]
# u_1_prime_bytes = data_received[128 * 2: 128 * 3]
# u_2_prime_bytes = data_received[128 * 3: 128 * 4]
# Y_bytes = data_received[128 * 4: 128 * 5]
# t_prime_bytes = data_received[128 * 5 : 128 * 5 + 20]
# Y_value = Conversion.OS2IP(Y_bytes, True)
# hp_1_prime_value = Conversion.OS2IP(hp_1_prime_bytes, True)
# hp_2_prime_value = Conversino.OS2IP(hp_2_prime_bytes, True)
# u_1_prime_value = Conversion.OS2IP(u_1_prime_bytes, True)
# u_2_prime_value = Conversion.OS2IP(u_2_prime_bytes, True)

# K_A_1_value = (Y_value ** x_value) % group.p

d_value = Conversion.OS2IP(d_bytes, True) % group_order
dr_value = (d_value * r_value) % group_order
# val1 = (hp_1_prime_value ** r_value) % group.p
# val2 = (hp_2_prime_value ** dr_value) % group.p
# K_A_2_value = (val1 * val2) % group.p

# val1 = (alpha_1_value + d_value * beta_1_value) % group_order
# val2 = (alpha_2_value + d_value * beta_2_value) % group_order
# tmp1 = (u_1_prime_value ** val1) % group.p
# tmp2 = (u_2_prime_value ** val2) % group.p
# K_A_3_value = (tmp1 * tmp2) % group.p

# K_A_1_bytes = Conversion.IP2OS(K_A_1_value, 128)
# K_A_2_bytes = Conversion.IP2OS(K_A_2_value, 128)
# K_A_3_bytes = Conversion.IP2OS(K_A_3_value, 128)
# # calculate bitwise XOR
# result = b''
# for i in range(0, 128):
# 	result += six.int2byte(K_A_1_bytes[i] ^ K_A_2_bytes[i] ^ K_A_3_bytes[i])
# for i in range(0, 20):
# 	result += six.int2byte(t_bytes[i] ^ t_prime_bytes[i])
# # hash result to get s_A
# s_A_bytes = waters.sha2(result)
# s_A_bytes = s_A_bytes[0:16] # get the first 128 bits
# prf = MYPRF(s_A_bytes)
# SK_A_bytes = prf._encrypt(to_send + data_received)
# print(SK_A_bytes)

print('haha')
# print('closing socket')
# sock.close()