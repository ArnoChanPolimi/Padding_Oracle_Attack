function state_out = add_round_key (state_in, round_key)
%ADD_ROUND_KEY  Add (XOR) the round key to the state.
%
%   STATE_OUT = ADD_ROUND_KEY (STATE_IN, ROUND_KEY) 
%   adds the current round key matrix ROUND_KEY 
%   to the current state matrix STATE_IN.
%   Adding in GF(2^8) is performed via bitwise XOR.


% Add state (matrix) and round key (matrix) via bitwise XOR
state_out = bitxor ((state_in), (round_key));