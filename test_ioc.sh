#!/bin/bash

# Criar arquivo binário com IPs embutidos (para teste de IoCs)
# Inclui: IP fora da rede (185.220.101.45), IPs a serem filtrados (127.0.0.1, 0.0.0.0, 192.168.1.1)

printf '\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00\x78\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' > test_binary.elf

# Adicionar string com IPs
printf 'Contact C2 at 185.220.101.45\x00' >> test_binary.elf
printf 'Fallback: 93.184.216.34\x00' >> test_binary.elf
printf 'Ignored: 127.0.0.1\x00' >> test_binary.elf
printf 'Ignored: 0.0.0.0\x00' >> test_binary.elf
printf 'Ignored: 192.168.1.1\x00' >> test_binary.elf

# Adicionar shellcode pattern (xor rax, rax + syscall)
printf '\x48\x31\xC0\x0F\x05' >> test_binary.elf

chmod +x test_binary.elf

echo "Arquivo de teste criado: test_binary.elf"
