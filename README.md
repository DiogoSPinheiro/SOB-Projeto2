# SOB-Projeto2 File System Minix criptografado

Este projeto tem como objetivo a implementação de um sistema de arquivos minix cifrado que faz uso da API criptográfica do kernel Linux, que armazena arquivos de forma cifrada. 

Neste Projeto é utilizado um programa auxiliar user e o arquivo file.c do sistema de arquivos minix:

Programa user
------------
Este programa tem como objetivo realizar a leitura ou escrita de um determinado arquivo fornecido localizado na partição a qual o minix está instalado.

Arquivo file.c 
------------
Neste arquivo duas fuções foram modificadas, de leitura genérica e escrita genérica, foram substituídas por funções de criptografar na escrita e descriptografar na leitura.

Integrantes:
* Daniel Toloto: dctoloto@gmail.com
* Diogo Pinheiro: diogo.7.pinheiro@hotmail.com  
* Rodrigo Machado: rodrigomachado161@gmail.com
