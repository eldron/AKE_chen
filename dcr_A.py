import socket
import sys
import six
import time
from charm.core.math.integer import random, randomPrime, randomBits, isPrime, gcd, toInt
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import PairingGroup
from sha2 import Waters
from MYPRF import MYPRF

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to party B
server_address = ('localhost', 10000)


# calculate length of group elements
security_level = 128 # this value can be 80, 112, 128, 256
bits = 1024
if security_level == 80:
	bits = 1024
elif security_level == 112:
	bits = 2048
elif security_level == 128:
	bits = 3072
elif security_level == 256:
	bits = 15360

prime_bits = bits // 2
group_order_bits = 2 * security_level

# generate p, p_prime, q, q_prime
p = 0
p_prime = 0
q = 0
q_prime = 0
while True:
	p = randomPrime(prime_bits, 1)
	p_prime = (p - 1) / 2
	if(isPrime(p) and isPrime(p_prime)):
		break

while True:
	q = randomPrime(prime_bits, 1)
	q_prime = (q - 1) / 2
	if(isPrime(q) and isPrime(q_prime)):
		break
N = p * q
group_order = 2 * p_prime * q_prime # order of L_DCR
N_square = N * N

print('p = ', p)
print('q = ', q)
# search the generator for L_DCR
tmp = 0
while True:
	tmp = random(N_square)
	if(gcd(tmp, N_square) == 1):
		break

val1 = (tmp ** (2 * N)) % N_square
print('val1 = ', val1)
print('toInt(val1) = ', toInt(val1))
g = N_square - toInt(val1)
g = g % N_square
print('g = ', g)

alpha_value = random(N_square / 2) # of length bits
beta_value = random(N_square / 2)
hp_1_value = (g ** alpha_value) % N_square
hp_2_value = (g ** beta_value) % N_square

# t_1(k) and u(k) are calculated from the length of r and x
t_1_length = 2 * group_order_bits - 128 # length of IV is 16 bytes
u_length = 2 * group_order_bits - 128

r_1_value = randomBits(t_1_length)
r_2_value = randomBits(640) # the length of r2 does not matter
r_1_bytes = Conversion.IP2OS(r_1_value, t_1_length // 8)
r_2_bytes = Conversion.IP2OS(r_2_value, 80)
t_value = randomBits(160) # the length of t does not matter
t_bytes = Conversion.IP2OS(t_value, 20)

# session execution
e_value = randomBits(u_length)
e_bytes = Conversion.IP2OS(e_value, u_length // 8)
# set l_1, l_2 (length of the output of extractor 1 and extractor 2) to be 128 bits, the length of AES key

# hash alpha, beta, r_1 together to get lsk_A_prime
group_for_hash = PairingGroup("SS512")
waters = Waters(group_for_hash)
alpha_bytes = Conversion.IP2OS(alpha_value, bits // 8)
beta_bytes = Conversion.IP2OS(beta_value, bits // 8)
lsk_A_prime = waters.sha2(alpha_bytes + beta_bytes + r_1_bytes)
lsk_A_prime = lsk_A_prime[0: 16]

# hash e and r_2 together to get esk_A_prime
esk_A_prime = waters.sha2(e_bytes + r_2_bytes)
esk_A_prime = esk_A_prime[0: 16]

# calculate r and w
prf1 = MYPRF(lsk_A_prime)
tmp1 = prf1._encrypt(e_bytes)
prf2 = MYPRF(esk_A_prime)
tmp2 = prf2._encrypt(r_1_bytes)
tmp1 = tmp1['CipherText']
tmp2 = tmp2['CipherText']
tmp = group_order_bits // 8
r_value = Conversion.OS2IP(tmp1[0: tmp], True) + Conversion.OS2IP(tmp2[0: tmp], True)
w_value = Conversion.OS2IP(tmp1[tmp: 2 * tmp], True) + Conversion.OS2IP(tmp2[tmp: 2 * tmp], True)
r_value = r_value % group_order
w_value = w_value % group_order

capital_W_value = (g ** w_value) % N_square
capital_X_value = (g ** r_value) % N_square
capital_W_bytes = Conversion.IP2OS(capital_W_value, bits // 8)
capital_X_bytes = Conversion.IP2OS(capital_X_value, bits // 8)

# send N, group_order, g, hp_1, hp_2, W, X, t to party B
N_bytes = Conversion.IP2OS(N, bits // 8)
g_bytes = Conversion.IP2OS(g, bits // 8)
group_order_bytes = Conversion.IP2OS(group_order, bits // 8)
hp_1_bytes = Conversion.IP2OS(hp_1_value, bits // 8)
hp_2_bytes = Conversion.IP2OS(hp_2_value, bits // 8)
to_send = N_bytes + group_order_bytes + g_bytes + hp_1_bytes + hp_2_bytes + capital_W_bytes + capital_X_bytes + t_bytes
sock.connect(server_address)
sock.sendall(to_send)

# receive hp_1_prime_bytes, hp_2_prime_bytes, capital_W_prime_bytes, capital_X_prime_bytes, t_prime_bytes from party B
element_size = bits // 8
amount_expected = 4 * element_size + len(t_bytes)
data_received = b''
while len(data_received) < amount_expected:
	data_received += sock.recv(amount_expected)

if(len(data_received) != amount_expected):
	print('length of data received from party B is not correct!!!')
else:
	print('data received from the party B')

hp_1_prime_bytes = data_received[0 : element_size]
hp_2_prime_bytes = data_received[element_size : 2 * element_size]
capital_W_prime_bytes = data_received[2 * element_size : 3 * element_size]
capital_X_prime_bytes = data_received[3 * element_size : 4 * element_size]
t_prime_bytes = data_received[4 * element_size : amount_expected]

hp_1_prime_value = Conversion.OS2IP(hp_1_prime_bytes, True)
hp_2_prime_value = Conversion.OS2IP(hp_2_prime_bytes, True)
capital_W_prime_value = Conversion.OS2IP(capital_W_prime_bytes, True)
capital_X_prime_value = Conversion.OS2IP(capital_X_prime_bytes, True)
t_prime_value = Conversion.OS2IP(t_prime_bytes, True)

hp_1_prime_value = hp_1_prime_value % N_square
hp_2_prime_value = hp_2_prime_value % N_square
capital_W_prime_value = capital_W_prime_value % N_square
capital_X_prime_value = capital_X_prime_value % N_square

# hash to_send and data_received together to get d
d_bytes = waters.sha2(to_send + data_received)
d_bytes = d_bytes[0 : group_order_bits // 8]
d_value = Conversion.OS2IP(d_bytes, True) % group_order

tmp = (capital_X_prime_value ** r_value) % N_square
K_A_1_value = (toInt(tmp) - toInt(tmp % N)) / N

tmp1 = (hp_1_prime_value ** w_value) % N_square
dw_value = (d_value * w_value) % group_order
tmp2 = (hp_2_prime_value ** dw_value) % N_square
tmp = (tmp1 * tmp2) % N_square
K_A_2_value = (tmp - toInt(tmp % N)) / N

tmp1 = (alpha_value + d_value * beta_value) % group_order
tmp = (capital_W_prime_value ** tmp1) % N_square
K_A_3_value = (tmp - toInt(tmp % N)) / N

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
