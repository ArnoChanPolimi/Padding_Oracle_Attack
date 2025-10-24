function [s_box, inv_s_box] = s_box_gen
%S_BOX_GEN  Create S-box and inverse S-box.
%
%   [S_BOX, INV_S_BOX] = S_BOX_GEN 
%   creates the S-box and the inverse S-box 
%   to be used by the function SUB_BYTES.
%   The S-box is created in two steps:
%   1. Take the multiplicative inverse of the finite field GF(2^8).
%   2. Apply an affine transformation.
%
%   [S_BOX, INV_S_BOX] = S_BOX_GEN (1) 
%   switches verbose mode on, that displays intermediate results.
%
%   S_BOX_GEN has to be called prior to 
%   KEY_EXPANSION, CIPHER, and INV_CIPHER.
%
%   In the AES Specification Standard the S-boxes are depicted
%   as arrays. For the sake of indexing-simplicity they are internally 
%   stored as vectors in this implementation.


% Define the irreducible polynomial 
% to be used in the modulo operation in poly_mult, 
% called by find_inverse
mod_pol = bin2dec ('100011011');

% The polynomial multiplicative inverse of zero is defined here as zero.
% Matlab vectors start with an index of "1"
inverse(1) = 0;

% Loop over all remaining byte values
for i = 1 : 255
    
    % Compute the multiplicative inverse of the current byte value
    % with respect to the specified modulo polynomial
    inverse(i + 1) = find_inverse (i, mod_pol);
    
end

% Loop over all byte values
for i = 1 : 256

    % Apply the affine transformation 
    s_box(i) = aff_trans (inverse(i));

end

% Create the inverse S-box by taking the values 
% of the elements of the S-Box as indices:
inv_s_box = s_box_inversion (s_box);

% Display intermediate result if requested
