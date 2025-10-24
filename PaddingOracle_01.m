
function alert=PaddingOracle_01(sub_ciphertext)
%Input: a submitted cipheretext in character format.
%Output: an alert indicating whether a padding error occured.
%If alert=1, %then a padding error was detected.
%If alert=0 no padding error was detected.
%The function is implemented as a black box decryptor.
%This choice was made to avoid declaring global variables.

addpath('AES');
seed=123456;
rng(seed);%we have fixed the initialization of any random number generator by using the seed

%%%%%%%%%%%%%%%% initializations %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%initializations
key = randi([0, 255],16,1)'; % we need 16 characters
key_nonce=randi([0, 255],16,1)'; % we need 16 characters
nonce=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
block_len=16;
IV = cipher(nonce, key_nonce);
recovered_plaintext=[];
flag=0;
num_chain=length(sub_ciphertext)/block_len; %length of the chain

%%%%%%%%%% CBC mode decipher %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
pre_input=IV;
for i=1:num_chain
    input=sub_ciphertext((i-1)*16+1:i*16);
    output=bitxor(inv_cipher(input, key), pre_input);
    pre_input=input;
    recovered_plaintext=[recovered_plaintext, output];
end


%%%%%%%%%%%%%%%% remove padding %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
if recovered_plaintext(end-15:end)==zeros(1, 16)
    padding_len=0;
    flag=1;
else
    for i=1:15
        if recovered_plaintext(end-i+1:end)==repmat(i, 1, i)
            padding_len=i;
            recovered_plaintext=recovered_plaintext(1:end-i);
            flag=1;
            break
        end
    end
end

%%%%%%%%%%%%%%%%%%%%% Check if an alert is needed %%%%%%%%%%%%%%%%%%%%%%%%%%
if flag==0
    plaintext=[];
    alert=1; %'Padding Error!'
else
    plaintext=char(recovered_plaintext);
    alert=0;
end
