import socket
import sys
import six
from charm.toolbox.integergroup import IntegerGroup
from charm.core.math.integer import *
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import PairingGroup
from sha2 import Waters
from MYPRF import MYPRF

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

	# long-term key generation, session execution, then session key output

	# receive group_p, group_order, g, g1, g2, hp1, hp2, u1, u2, X, t from party A
	#amount_expected = 128 * 10 + 20
	amount_expected = (9 * (bits // 8)) + (group_order_bits // 8) + 20
	data_received = b''
	while len(data_received) < amount_expected:
		data_received += connection.recv(amount_expected)

	element_size = bits // 8
	group_order_size = group_order_bits // 8
	group_p_bytes = data_received[0: element_size]
	group_order_bytes = data_received[element_size: element_size + group_order_size]
	g_bytes = data_received[element_size + group_order_size: element_size * 2 + group_order_size]
	g_1_bytes = data_received[element_size * 2 + group_order_size: element_size * 3 + group_order_size]
	g_2_bytes = data_received[element_size * 3 + group_order_size: element_size * 4 + group_order_size]
	hp_1_bytes = data_received[element_size * 4 + group_order_size: element_size * 5 + group_order_size]
	hp_2_bytes = data_received[element_size * 5 + group_order_size: element_size * 6 + group_order_size]
	u_1_bytes = data_received[element_size * 6 + group_order_size: element_size * 7 + group_order_size]
	u_2_bytes = data_received[element_size * 7 + group_order_size: element_size * 8 + group_order_size]
	X_bytes = data_received[element_size * 8 + group_order_size: element_size * 9 + group_order_size]
	t_bytes = data_received[element_size * 9 + group_order_size: amount_expected]

	group_p_value = Conversion.OS2IP(group_p_bytes, True)
	#group_q_value = Conversion.OS2IP(group_q_bytes, True)
	group_order = Conversion.OS2IP(group_order_bytes, True)
	#print('group.p = ', group_p_value)
	#print('group_order = ', group_order)
	g_value = Conversion.OS2IP(g_bytes, True)
	g_1_value = Conversion.OS2IP(g_1_bytes, True)
	g_2_value = Conversion.OS2IP(g_2_bytes, True)
	hp_1_value = Conversion.OS2IP(hp_1_bytes, True)
	hp_2_value = Conversion.OS2IP(hp_2_bytes, True)
	u_1_value = Conversion.OS2IP(u_1_bytes, True)
	u_2_value = Conversion.OS2IP(u_2_bytes, True)
	X_value = Conversion.OS2IP(X_bytes, True)
	t_value = Conversion.OS2IP(t_bytes, True)

	# group = IntegerGroup()
	# group.r = 2
	# group.setparam(group_p_value, group_q_value)
	# group_order = group.q

	#print('group order = ', group_order)
	g_value = g_value % group_p_value
	g_1_value = g_1_value % group_p_value
	g_2_value = g_2_value % group_p_value
	hp_1_value = hp_1_value % group_p_value
	hp_2_value = hp_2_value % group_p_value
	u_1_value = u_1_value % group_p_value
	u_2_value = u_2_value % group_p_value
	X_value = X_value % group_p_value

	alpha_1_prime_value = randomBits(group_order_bits) % group_order
	alpha_2_prime_value = randomBits(group_order_bits) % group_order
	beta_1_prime_value = randomBits(group_order_bits) % group_order
	beta_2_prime_value = randomBits(group_order_bits) % group_order
	#print('alpha_1_prime_value = ', alpha_1_prime_value)
	#print('alpha_2_prime_value = ', alpha_2_prime_value)
	#print('beta_1_prime_value = ', beta_1_prime_value)
	#print('beta_2_prime_value = ', beta_2_prime_value)

	alpha_1_prime_bytes = Conversion.IP2OS(alpha_1_prime_value, group_order_bits // 8)
	alpha_2_prime_bytes = Conversion.IP2OS(alpha_2_prime_value, group_order_bits // 8)
	beta_1_prime_bytes = Conversion.IP2OS(beta_1_prime_value, group_order_bits // 8)
	beta_2_prime_bytes = Conversion.IP2OS(beta_2_prime_value, group_order_bits // 8)

	# print('type of g_1 value is: ', type(g_1_value))
	# print('type of alpha1_prime_value is: ', type(alpha_1_prime_value))
	# print(g_1_value)
	# print('haha')
	# print(alpha_1_prime_value)
	tmp1 = (g_1_value ** alpha_1_prime_value) % group_p_value
	tmp2 = (g_2_value ** alpha_2_prime_value) % group_p_value
	hp_1_prime_value = (tmp1 * tmp2) % group_p_value
	tmp1 = (g_1_value ** beta_1_prime_value) % group_p_value
	tmp2 = (g_2_value ** beta_2_prime_value) % group_p_value
	hp_2_prime_value = (tmp1 * tmp2) % group_p_value

	t_1_length = 2 * group_order_bits - 128 # length of IV is 16 bytes
	u_length = 2 * group_order_bits - 128
	r_1_prime_value = randomBits(t_1_length)
	r_2_prime_value = randomBits(640) # length of r_2_prime does not matter
	r_1_prime_bytes = Conversion.IP2OS(r_1_prime_value, t_1_length // 8)
	r_2_prime_bytes = Conversion.IP2OS(r_2_prime_value, 80)
	t_prime_value = randomBits(160) # length of t_prime does not matter
	t_prime_bytes = Conversion.IP2OS(t_prime_value, 20)
	e_prime_value = randomBits(u_length)
	e_prime_bytes = Conversion.IP2OS(e_prime_value, u_length // 8)

	group_for_hash = PairingGroup("SS512")
	waters = Waters(group_for_hash)
	# hash alpha1_prime, alph2_prime, beta1_prime, beta2_prime, r1_prime together to get lsk_B_prime
	lsk_B_prime_bytes = waters.sha2(alpha_1_prime_bytes + alpha_2_prime_bytes + beta_1_prime_bytes + beta_2_prime_bytes + r_1_prime_bytes)
	lsk_B_prime_bytes = lsk_B_prime_bytes[0:16]

	# hash e_prime, r_2_prime together to get esk_B_prime_bytes
	esk_B_prime_bytes = waters.sha2(e_prime_bytes + r_2_prime_bytes)
	esk_B_prime_bytes = esk_B_prime_bytes[0:16]

	# calculate r_prime_value and y_value
	prf1 = MYPRF(lsk_B_prime_bytes)
	tmp1 = prf1._encrypt(e_prime_bytes)
	tmp1 = tmp1['CipherText']
	prf2 = MYPRF(esk_B_prime_bytes)
	tmp2 = prf2._encrypt(r_1_prime_bytes)
	tmp2 = tmp2['CipherText']
	r_prime_value = Conversion.OS2IP(tmp1[0: group_order_size], True) + Conversion.OS2IP(tmp2[0: group_order_size], True)
	r_prime_value = r_prime_value % group_order
	y_value = Conversion.OS2IP(tmp1[group_order_size: 2 * group_order_size], True) + Conversion.OS2IP(tmp2[group_order_size: 2 * group_order_size], True)
	y_value = y_value % group_order

	u_1_prime_value = (g_1_value ** r_prime_value) % group_p_value
	u_2_prime_value = (g_2_value ** r_prime_value) % group_p_value
	Y_value = (g_value ** y_value) % group_p_value

	# send hp_1_prime_value, hp_2_prime_value, u_1_prime_value, u_2_prime_value, Y_value, t_prime_value to party A
	hp_1_prime_bytes = Conversion.IP2OS(hp_1_prime_value, bits // 8)
	hp_2_prime_bytes = Conversion.IP2OS(hp_2_prime_value, bits // 8)
	u_1_prime_bytes = Conversion.IP2OS(u_1_prime_value, bits // 8)
	u_2_prime_bytes = Conversion.IP2OS(u_2_prime_value, bits // 8)
	Y_bytes = Conversion.IP2OS(Y_value, bits // 8)
	to_send = hp_1_prime_bytes + hp_2_prime_bytes + u_1_prime_bytes + u_2_prime_bytes + Y_bytes + t_prime_bytes
	connection.sendall(to_send)

	# hash data received and sent together to get d
	d_bytes = waters.sha2(data_received + to_send)
	d_bytes = d_bytes[0: group_order_size]
	d_value = Conversion.OS2IP(d_bytes, True)
	d_value = d_value % group_order

	K_B_1_value = (X_value ** y_value) % group_p_value

	tmp1 = (alpha_1_prime_value + d_value * beta_1_prime_value) % group_order
	tmp2 = (alpha_2_prime_value + d_value * beta_2_prime_value) % group_order
	val1 = (u_1_value ** tmp1) % group_p_value
	val2 = (u_2_value ** tmp2) % group_p_value
	K_B_2_value = (val1 * val2) % group_p_value

	val1 = (hp_1_value ** r_prime_value) % group_p_value
	tmp = (d_value * r_prime_value) % group_order
	val2 = (hp_2_value ** tmp) % group_p_value
	K_B_3_value = (val1 * val2) % group_p_value

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
	#print(SK_B_bytes['CipherText'])
	#print('hello')
