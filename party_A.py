import socket
import sys
import six
import time
from charm.core.math.integer import random, randomPrime, randomBits, isPrime
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import PairingGroup
from sha2 import Waters
from MYPRF import MYPRF

from length_functions import *


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to party B
server_address = ('localhost', 10000)



# long-term key generation, session execution, then session key output

# generate the group G
security_level = 128 # this value can be 80, 112, 128, 256
# calculate length of group elements
bits = 1024
if security_level == 80:
	bits = 1024
elif security_level == 112:
	bits = 2048
elif security_level == 128:
	bits = 3072
elif security_level == 256:
	bits = 15360

group_order_bits = 2 * security_level
group_p = 0 # the prime number for mod calculation

group_order = randomPrime(group_order_bits)
#print('group_order = ', group_order)

while True:
	random_k_value = randomBits(bits - group_order_bits)
	group_p = random_k_value * group_order + 1
	if isPrime(group_p):
		break
#print('group_p = ', group_p)

group_g = 0
while True:
	i = random(group_p)
	tmp1 = (group_p - 1) / group_order
	tmp2 = (i ** tmp1) % group_p
	if tmp2 != 1 and i > 1:
		group_g = tmp2
		break

#print('group_g = ', group_g)
time1 = time.time()

alpha_1_value = randomBits(group_order_bits) % group_order
alpha_2_value = randomBits(group_order_bits) % group_order
beta_1_value = randomBits(group_order_bits) % group_order
beta_2_value = randomBits(group_order_bits) % group_order
alpha_1_bytes = Conversion.IP2OS(alpha_1_value, group_order_bits // 8)
alpha_2_bytes = Conversion.IP2OS(alpha_2_value, group_order_bits // 8)
beta_1_bytes = Conversion.IP2OS(beta_1_value, group_order_bits // 8)
beta_2_bytes = Conversion.IP2OS(beta_2_value, group_order_bits // 8)

# two random generators of group G
g_1 = 1
g_2 = 1
while True:
	g_1 = (group_g ** random(group_order)) % group_p
	if g_1 != 1 and g_1 != group_g:
		break

while True:
	g_2 = (group_g ** random(group_order)) % group_p
	if g_2 != 1 and g_1 != group_g:
		break

g_1_bytes = Conversion.IP2OS(g_1, bits // 8)
g_2_bytes = Conversion.IP2OS(g_2, bits // 8)
g_bytes = Conversion.IP2OS(group_g, bits // 8)

tmp1 = (g_1 ** alpha_1_value) % group_p
tmp2 = (g_2 ** alpha_2_value) % group_p
hp_1 = (tmp1 * tmp2) % group_p
tmp1 = (g_1 ** beta_1_value) % group_p
tmp2 = (g_2 ** beta_2_value) % group_p
hp_2 = (tmp1 * tmp2) % group_p
hp = {'hp_1':hp_1, 'hp_2':hp_2}
hp_1_bytes = Conversion.IP2OS(hp_1, bits // 8)
hp_2_bytes = Conversion.IP2OS(hp_2, bits // 8)

# generate r_1, r_2, t
# currently set t_1(k) to 192 bits, t_2(k) to 640 bits, u(k) to 192 bits, t_3(k) to 160 bits
# t_1(k) and u(k) are calculated from the length of r and x
t_1_length = 2 * group_order_bits - 128 # length of IV is 16 bytes
u_length = 2 * group_order_bits - 128

r_1_value = randomBits(t_1_length)
r_2_value = randomBits(640) # the length of r2 does not matter
r_1_bytes = Conversion.IP2OS(r_1_value, t_1_length // 8)
r_2_bytes = Conversion.IP2OS(r_2_value, 80)
t_value = randomBits(160) # the length of t does not matter
t_bytes = Conversion.IP2OS(t_value, 20)

time2 = time.time()


# session execution
e_value = randomBits(u_length)
e_bytes = Conversion.IP2OS(e_value, u_length // 8)
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
tmp = group_order_bits // 8
r_value = Conversion.OS2IP(tmp1[0: tmp], True) + Conversion.OS2IP(tmp2[0: tmp], True)
x_value = Conversion.OS2IP(tmp1[tmp: 2 * tmp], True) + Conversion.OS2IP(tmp2[tmp: 2 * tmp], True)
r_value = r_value % group_order
x_value = x_value % group_order

u_1_value = (g_1 ** r_value) % group_p
u_2_value = (g_2 ** r_value) % group_p
X_value = (group_g ** x_value) % group_p
# send group.p, group.q, g, g1, g2, hp1, hp2, u1, u2, X, t to party B
u_1_bytes = Conversion.IP2OS(u_1_value, bits // 8)
u_2_bytes = Conversion.IP2OS(u_2_value, bits // 8)
X_bytes = Conversion.IP2OS(X_value, bits // 8)


time3 = time.time()


group_p_bytes = Conversion.IP2OS(group_p, bits // 8)
group_order_bytes = Conversion.IP2OS(group_order, group_order_bits // 8)
to_send = group_p_bytes + group_order_bytes + g_bytes + g_1_bytes + g_2_bytes + hp_1_bytes + hp_2_bytes + u_1_bytes + u_2_bytes + X_bytes + t_bytes
	
#print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)
sock.sendall(to_send)
#print('data sent')

# receive from party B
amount_expected = len(hp_1_bytes + hp_2_bytes + u_1_bytes + u_2_bytes + X_bytes + t_bytes)
data_received = b''
while len(data_received) < amount_expected:
	data_received += sock.recv(amount_expected)

if(len(data_received) != amount_expected):
	print('length of data received from party B is not correct!!!')
else:
	print('data received from the party B')


time4 = time.time()

# hash data sent and received together to get d, length of d is group_order_bits
d_bytes = waters.sha2(to_send + data_received)
d_bytes = d_bytes[0: group_order_bits // 8]
element_size = bits // 8
hp_1_prime_bytes = data_received[0: element_size]
hp_2_prime_bytes = data_received[element_size: element_size * 2]
u_1_prime_bytes = data_received[element_size * 2: element_size * 3]
u_2_prime_bytes = data_received[element_size * 3: element_size * 4]
Y_bytes = data_received[element_size * 4: element_size * 5]
t_prime_bytes = data_received[element_size * 5 : element_size * 5 + 20]
Y_value = Conversion.OS2IP(Y_bytes, True)
Y_value = Y_value % group_p
hp_1_prime_value = Conversion.OS2IP(hp_1_prime_bytes, True)
hp_2_prime_value = Conversion.OS2IP(hp_2_prime_bytes, True)
u_1_prime_value = Conversion.OS2IP(u_1_prime_bytes, True)
u_2_prime_value = Conversion.OS2IP(u_2_prime_bytes, True)
hp_1_prime_value = hp_1_prime_value % group_p
hp_2_prime_value = hp_2_prime_value % group_p
u_1_prime_value = u_1_prime_value % group_p
u_2_prime_value = u_2_prime_value % group_p

K_A_1_value = (Y_value ** x_value) % group_p

d_value = Conversion.OS2IP(d_bytes, True) % group_order
dr_value = (d_value * r_value) % group_order
val1 = (hp_1_prime_value ** r_value) % group_p
val2 = (hp_2_prime_value ** dr_value) % group_p
K_A_2_value = (val1 * val2) % group_p

val1 = (alpha_1_value + d_value * beta_1_value) % group_order
val2 = (alpha_2_value + d_value * beta_2_value) % group_order
tmp1 = (u_1_prime_value ** val1) % group_p
tmp2 = (u_2_prime_value ** val2) % group_p
K_A_3_value = (tmp1 * tmp2) % group_p

K_A_1_bytes = Conversion.IP2OS(K_A_1_value, bits // 8)
K_A_2_bytes = Conversion.IP2OS(K_A_2_value, bits // 8)
K_A_3_bytes = Conversion.IP2OS(K_A_3_value, bits // 8)
# calculate bitwise XOR
result = b''
for i in range(0, bits // 8):
	result += six.int2byte(K_A_1_bytes[i] ^ K_A_2_bytes[i] ^ K_A_3_bytes[i])
for i in range(0, 20):
	result += six.int2byte(t_bytes[i] ^ t_prime_bytes[i])
# hash result to get s_A
s_A_bytes = waters.sha2(result)
s_A_bytes = s_A_bytes[0:16] # get the first 128 bits
prf = MYPRF(s_A_bytes)
SK_A_bytes = prf._encrypt(to_send + data_received)

time5 = time.time()

long_term_key_generation_time = time2 - time1
session_execution_time = time3 - time2
network_delay = time4 - time3
session_key_output_time = time5 - time4

print('long term key generation time = ', long_term_key_generation_time)
print('session execution time = ', session_execution_time)
#print('network delay = ', network_delay)
print('session key output time = ', session_key_output_time)
print('network consumption = ', len(to_send + data_received), 'bytes')

tmp = input('input anything to continue')
# print(SK_A_bytes['CipherText'])
# print('haha')
# print('closing socket')
# sock.close()