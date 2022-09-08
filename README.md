# kpwdenc
/*
	Esse algoritmo é um simples codificador de senhas
	que trabalha como um "embaralhador" de caracteres.
	
	Como funciona?
	
	Primeiro é gerado um array com caracteres aleatórios, chamado
	DATA. Depois é gerado um array denominado PRV_KEY, onde
	conterá os índices correspondentes aos dados originais
	armazenados em DATA.
	
	Basicamente PRV_KEY revela os índices de DATA que correspondem
	a senha. Sem ter conhecimento de PRV_KEY, isto é, saber seu
	valor, fica impossível descobrir a senha, visto que todos os
	caracteres de DATA podem fazer parte da senha.
	
	Recomendo o uso desse algoritmo para uma senha de até 32 dígitos.
	Sendo codificada uma senha com letras, números e caracteres especiais,
	fica impossível decifrá-la sem conhecer PRV_KEY, o qual revela os
	caracteres da senha.
	
	Como testar: gcc kpwd_encrypt.c -o kpwdenc
	
	Codificando:
		./kpwdenc e minhasenha meulembrete
		
	Decodificando:
		./kpwdenc d meulembrete.dat meulembrete.key
*/
