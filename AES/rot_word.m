function w_out = rot_word (w_in)
%ROT_WORD  Rotate the elements of a four element vector.
%
%   W_OUT = ROT_WORD (W_IN) 
%   performs a cyclic shift of the elements 
%   of the four element vector W_IN.
%   [a1, a2, a3, a4] --> [a2, a3, a4, a1]

% Do the shift...
w_out = w_in([2 3 4 1]);