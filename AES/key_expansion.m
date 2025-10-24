function w = key_expansion (key, s_box, rcon)
%KEY_EXPANSION  Expand the 16-byte cipher key.
%
%   W = KEY_EXPANSION (KEY, S_BOX, RCON) 
%   creates the 44x4-byte expanded key W,
%   using the initial 16-byte cipher KEY, 
%   the predefined byte substitution table S_BOX, and
%   the round constant RCON to be added to every fourth 16-byte sub-key.
%
%   W = KEY_EXPANSION (KEY, S_BOX, RCON, 1) 
%   switches verbose mode on, that displays intermediate results.
%
%   KEY has to be a vector of 16 bytes (0 <= KEY(i) <= 255).
%
%   KEY_EXPANSION has to be called prior to CIPHER and INV_CIPHER.

% If there is an optional "verbose mode" argument


% If the key vector is a cell array or does not have 16 elements
if iscell (key) | prod (size (key)) ~= 16

    % Inform user and abort
    error ('Key has to be a vector (not a cell array) with 16 elements.')
    
end

% If any element of the key vector cannot be represented by 8 bits
if any (key < 0 | key > 255)
    
    % Inform user and abort
    error ('Elements of key vector have to be bytes (0 <= key(i) <= 255).')
    
end



% Copy the 16 elements of the key vector row-wise 
% into the first four rows of the expanded key
w = (reshape (key, 4, 4))';


% Loop over the rest of the 44 rows of the expanded key
for i = 5 : 44
    
    % Copy the previous row of the expanded key into a buffer
    temp = w(i - 1, :);

    % Every fourth row is treated differently:
    if mod (i, 4) == 1
    
        % Perform a cyclic (byte-wise) permutation to the buffer
        temp = rot_word (temp);
        
     
    
        % Substitute all 4 elements of the buffer
        % by shoving them through the S-box
        temp = double(sub_bytes (temp, s_box));

        
        % Compute the current round constant
        r = double(rcon ((i - 1)/4, :));

       
        
        % Add (XOR) the current rount constant 
        % to every element of the buffer
        temp = bitxor (temp, r);

       
    end

    % The new row of the expanded key
    % is the sum (XOR) of the row four rows before
    % and the buffer
    w(i, :) = bitxor (w(i - 4, :), temp);
    
    
end