import socket
import sys
import six
from charm.toolbox.integergroup import IntegerGroup
from charm.core.math.integer import *
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import PairingGroup
from sha2 import Waters
from MYPRF import MYPRF

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

prime_bits = bits // 4
group_order_bits = 2 * security_level

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)
sock.listen(1)

while True:
	# wait for party A to connect
	print('waiting for a connection')
	connection, client_address = sock.accept()

	print('connection from', client_address)

	# receive N, group_order, g, hp_1, hp_2, W, X, t from party A
	element_size = bits // 8
	amount_expected = 7 * element_size + 20
	data_received = b''
	while len(data_received) < amount_expected:
		data_received += connection.recv(amount_expected)

	N_bytes = data_received[0: element_size]
	group_order_bytes = data_received[element_size : 2 * element_size]
	g_bytes = data_received[2 * element_size : 3 * element_size]
	hp_1_bytes = data_received[3 * element_size : 4 * element_size]
	hp_2_bytes = data_received[4 * element_size : 5 * element_size]
	capital_W_bytes = data_received[5 * element_size : 6 * element_size]
	capital_X_bytes = data_received[6 * element_size : 7 * element_size]
	t_bytes = data_received[7 * element_size : amount_expected]

	N_value = Conversion.OS2IP(N_bytes, True)
	group_order = Conversion.OS2IP(group_order_bytes, True)
	g_value = Conversion.OS2IP(g_bytes, True)
	hp_1_value = Conversion.OS2IP(hp_1_bytes, True)
	hp_2_value = Conversion.OS2IP(hp_2_bytes, True)
	capital_W_value = Conversion.OS2IP(capital_W_bytes, True)
	capital_X_value = Conversion.OS2IP(capital_X_bytes, True)
	t_value = Conversion.OS2IP(t_bytes, True)

	N_square = N_value ** 2
	g_value = g_value % N_square
	hp_1_value = hp_1_value % N_square
	hp_2_value = hp_2_value % N_square
	capital_X_value = capital_X_value % N_square
	capital_W_value = capital_W_value % N_square

	# long term key generation
	alpha_prime_value = random(N_square / 2 )
	beta_prime_value = random(N_square / 2)
	hp_1_prime_value = (g_value ** alpha_prime_value) % N_square
	hp_2_prime_value = (g_value ** beta_prime_value) % N_square

	# t_1(k) and u(k) are calculated from the length of r and x
	t_1_length = 2 * group_order_bits - 128 # length of IV is 16 bytes
	u_length = 2 * group_order_bits - 128

	r_1_prime_value = randomBits(t_1_length)
	r_2_prime_value = randomBits(640) # the length of r2 does not matter
	r_1_prime_bytes = Conversion.IP2OS(r_1_prime_value, t_1_length // 8)
	r_2_prime_bytes = Conversion.IP2OS(r_2_prime_value, 80)
	t_prime_value = randomBits(160) # the length of t does not matter
	t_prime_bytes = Conversion.IP2OS(t_prime_value, 20)

	# session execution
	e_prime_value = randomBits(u_length)
	e_prime_bytes = Conversion.IP2OS(e_prime_value, u_length // 8)
	# set l_1, l_2 (length of the output of extractor 1 and extractor 2) to be 128 bits, the length of AES key
	
	# hash alpha_prime, beta_prime, r_1_prime together to get lsk_B_prime
	group_for_hash = PairingGroup("SS512")
	waters = Waters(group_for_hash)
	alpha_prime_bytes = Conversion.IP2OS(alpha_prime_value, bits // 8)
	beta_prime_bytes = Conversion.IP2OS(beta_prime_value, bits // 8)
	lsk_B_prime = waters.sha2(alpha_prime_bytes + beta_prime_bytes + r_1_prime_bytes)
	lsk_B_prime = lsk_B_prime[0 : 16]

	# hash e_prime, r_2_prime together to get esk_B_prime
	esk_B_prime = waters.sha2(e_prime_bytes + r_2_prime_bytes)
	esk_B_prime = esk_B_prime[0 : 16]

	# calculate r_prime, w_prime
	prf1 = MYPRF(lsk_B_prime)
	tmp1 = prf1._encrypt(e_prime_bytes)
	prf2 = MYPRF(esk_B_prime)
	tmp2 = prf2._encrypt(r_1_prime_bytes)
	tmp1 = tmp1['CipherText']
	tmp2 = tmp2['CipherText']
	tmp = group_order_bits // 8
	r_prime_value = Conversion.OS2IP(tmp1[0: tmp], True) + Conversion.OS2IP(tmp2[0: tmp], True)
	w_prime_value = Conversion.OS2IP(tmp1[tmp: 2 * tmp], True) + Conversion.OS2IP(tmp2[tmp: 2 * tmp], True)
	r_prime_value = r_prime_value % group_order
	w_prime_value = w_prime_value % group_order

	capital_W_prime_value = (g_value ** w_prime_value) % N_square
	capital_X_prime_value = (g_value ** r_prime_value) % N_square

	# send hp_1_prime_value, hp_2_prime_value, capital_W_prime_value, capital_X_prime_value, t_prime_value to part A
	hp_1_prime_bytes = Conversion.IP2OS(hp_1_prime_value, bits // 8)
	hp_2_prime_bytes = Conversion.IP2OS(hp_2_prime_value, bits // 8)
	capital_W_prime_bytes = Conversion.IP2OS(capital_W_prime_value, bits // 8)
	capital_X_prime_bytes = Conversion.IP2OS(capital_X_prime_value, bits // 8)
	to_send = hp_1_prime_bytes + hp_2_prime_bytes + capital_W_prime_bytes + capital_X_prime_bytes + t_prime_bytes
	connection.sendall(to_send)

	# hash data_received and to_send together to get d
	d_bytes = waters.sha2(data_received + to_send)
	d_bytes = d_bytes[0 : group_order_bits // 8]
	d_value = Conversion.OS2IP(d_bytes, True) % group_order

	tmp = (capital_X_value ** r_prime_value) % N_square
	K_B_1_value = tmp / N_value

	tmp1 = (alpha_prime_value + d_value * beta_prime_value) % group_order
	tmp = (capital_W_value ** tmp1) % N_square
	K_B_2_value = tmp / N_value

	val1 = (hp_1_value ** w_prime_value) % N_square
	dwprime = (d_value * w_prime_value) % group_order
	val2 = (hp_2_value ** dwprime) % N_square
	tmp = (val1 * val2) % N_square
	K_B_3_value = tmp / N_value

	# calculate bitwise XOR
	K_B_1_bytes = Conversion.IP2OS(K_B_1_value, bits // 8)
	K_B_2_bytes = Conversion.IP2OS(K_B_2_value, bits // 8)
	K_B_3_bytes = Conversion.IP2OS(K_B_3_value, bits // 8)
	result = b''
	for i in range(0, bits // 8):
		result += six.int2byte(K_B_1_bytes[i] ^ K_B_2_bytes[i] ^ K_B_3_bytes[i])
	for i in range(0, 20):
		result += six.int2byte(t_bytes[i] ^ t_prime_bytes[i])

	s_B_bytes = waters.sha2(result)
	s_B_bytes = s_B_bytes[0:16]
	prf = MYPRF(s_B_bytes)
	SK_B_bytes = prf._encrypt(data_received + to_send)