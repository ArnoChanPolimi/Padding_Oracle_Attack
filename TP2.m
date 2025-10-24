%% TP: Padding Oracle Attack - Part2

%% %%%%%%%%%%  --- Read Me ---  %%%%%%%%% %%
% If you want to run this code, please make sure to rename the function **“PaddingOracle_01”** to its correct name.
% You may also need to add the following line inside the **“PaddingOracle_01”** function: addpath('AES');
%% %%%%%%%%%%  --- Read Me ---  %%%%%%%%% %%



%%
clear; clc;

% 64-byte example ciphertext (provided)
Cipher = [152 182 162 107 74 151 206 122 49 166 194 235 125 70 14 8, ...
     232 202 138 150 18 231 233 212 131 197 38 38 106 84 160 247, ...
     168 206 1 7 187 209 215 7 29 245 96 133 28 203 62 37, ...
     235 183 132 7 86 36 16 78 199 197 123 104 129 45 218 153];
num_block = ceil(length(Cipher) / 16);

Cipher = uint8(Cipher(:)).';
blocks = reshape(Cipher,16,[]).'; 
Ipos = zeros(num_block, 16, 'uint8');
Msg = zeros(num_block, 16, 'uint8');

found = false;
found_v = uint8(0);

%%%
g_start = 0;
reset = 0;
%%%


% Enumerate all possible values for Cprev_mod(pos)
% for b = num_block:-1:1
for b = 2:num_block
    fprintf('================ Block = %d ===================\n', b);
    % if b == 1
    %     C_prev_orig = zeros(1, 16, 'uint8');
    % else
        C_prev_orig = blocks(b - 1, :);   % previous block
    % end
    C_curr = blocks(b, :);                % current block

    Cprev_mod = C_prev_orig;
    C_prev_new = Cprev_mod;

    i = 0;
    while i < 16
        i = i + 1;
        pos = 16 - i + 1;
        Cprev_mod_old = uint8(C_prev_orig(pos)); % linked to original old byte value
        if i == 16
            pad = uint8(0);                  
        else 
            pad = uint8(i);        % current target padding (0x01, 0x02, ...)
        end
        found_this_byte = false;

        % Prepare modified previous block for the next padding length (pad_next = i+1)
        if i > 1 % since pad changed, update bytes after pos
            fprintf('LOG: Cprev_mod_old(%d) = %d;\n', pos, Cprev_mod_old); % print old value of current byte (original)
            for j = pos+1:16
                Cprev_mod(j) = bitxor(Ipos(b, j), pad); % set each byte after pos according to the new padding using I and pad
                fprintf('LOG: Cprev_mod_new(%d/16) = %d, using I and pad(0x%02x) to get new value.\n', j, Cprev_mod(j), pad);
            end            
            fprintf('\n');
        else 
            fprintf('LOG: Cprev_mod_old(%d) = %d;\n', pos, Cprev_mod_old);
        end    
        
        if reset == 1
            g_start = g_prev + 1;
            fprintf('LOG: reset = 1, g_start = %d, pad = %d (decimal);\n', g_start, pad);
        else
            g_start = 0;
        end
        for g = g_start:255
            reset = 0;
            if i == 16
                pad = uint8(0);
                guess = bitxor(uint8(g), pad);               
                Cprev_mod(pos) = bitxor(Cprev_mod_old, guess);
                fprintf('LOG: First byte (i=16), setting pad = 0x%2X;\n', pad);
            else
                guess = bitxor(uint8(g), pad);
                Cprev_mod(pos) = bitxor(Cprev_mod_old, guess);
            end

            fprintf('LOG: Cprev_mod(%d) = %d (g = %d)\n', pos, Cprev_mod(pos), g);
            % Cast to double for compatibility with internal implementation
            alert = PaddingOracle_01(double([Cprev_mod, C_curr]));  % alert==0 -> valid padding
            fprintf('LOG: alert(%d) = %d\n', b, alert);
            if alert == 0
                g_prev = g; % record a g that satisfies the oracle (there may be multiple)
                fprintf('\n');
                found = true;

                fprintf('*** Found Valid: guess = g XOR pad = %d XOR %d = %d (decimal) ***\n', g, pad, bitxor(g, pad));
                % From I[pos] XOR v = pad, derive I[pos]
                Ipos(b, pos) = bitxor(uint8(Cprev_mod(pos)), pad);

                fprintf('--- I%d(%d) = 0x%02X (%d in decimal) ---\n', b, pos, Ipos(b, pos), Ipos(b, pos));
                found_this_byte = true;
                fprintf('\n');
                break;
            end
        end
        if ~found_this_byte
            if g == 255 && i > 1
                g = g_prev;
                i = i - 2;
                reset = 1;
                continue;
            else
                error('Block %d, pos %d (pad=%d): no valid g in 0..255. Check oracle semantics.', ...
                b, pos, i);
            end
        end

    end
    % Compute plaintext block: P = I XOR C_prev
    Msg(b,:) = bitxor(uint8(Ipos(b, :)), uint8(C_prev_orig));
end

num_pad = Msg(num_block, 16);

% Display recovered message blocks in hex
Msg_blocks = reshape(Msg,16,[]).'; 

for block = 1:num_block
    fprintf('%02X ', Msg_blocks(block, :));
    fprintf('\n');
end

Msg_without_padding = Msg;
Msg_without_padding(num_block, 16-num_pad : 16) = [];
% Display ASCII form of recovered plaintext
Msg_ascii = char(Msg_without_padding);

disp(Msg_ascii);
