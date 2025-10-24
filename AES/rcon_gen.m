function rcon = rcon_gen
%RCON_GEN  Create round constants.
%
%   RCON = RCON_GEN 
%   creates the round constants vector RCON
%   to be used by the function KEY_EXPANSION.
%
%   RCON = RCON_GEN (1)
%   switches verbose mode on, that displays intermediate results.
%
%   RCON_GEN has to be called prior to KEY_EXPANSION.

% If there is an optional "verbose mode" argument


% Define the irreducible polynomial 
% to be used in the modulo operation in poly_mult
mod_pol = bin2dec ('100011011');

% The (first byte of the) first round constant is a "1"
rcon(1) = 1;

% Loop over the rest of the elements of the round constant vector
for i = 2 : 10

    % The next round constant is twice the previous one; modulo 
    rcon(i) = poly_mult (rcon(i-1), 2, mod_pol);
    
end

% The other (LSB) three bytes of all round constants are zeros
rcon = [rcon(:), zeros(10, 3)];

 
