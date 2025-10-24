function [poly_mat, inv_poly_mat] = poly_mat_gen
%POLY_MAT  Create polynomial coefficient matrices.
%
%   [POLY_MAT, INV_POLY_MAT] = POLY_MAT_GEN 
%   creates the polynomial coefficient matrices
%   to be used by the function MIX_COLUMNS.
%
%   [POLY_MAT, INV_POLY_MAT] = POLY_MAT_GEN (1)
%   switches verbose mode on, that displays intermediate results.
%
%   POLY_MAT_GEN has to be called prior to CIPHER and INV_CIPHER.

% If there is an optional "verbose mode" argument


% Define the first row of the polynomial coefficient matrix
% to be used in MIX_COLUMNS in hexadecimal representation.
% Small values are chosen for computational speed reasons
row_hex = {'02' '03' '01' '01'};

% Convert the polynomial coefficients to decimal "numbers"
% row = [2 3 1 1]
row = hex2dec (row_hex)';

% Construct a matrix with identical rows
% rows = [2 3 1 1]
%        [2 3 1 1]
%        [2 3 1 1]
%        [2 3 1 1]
rows = repmat (row, 4, 1);

% Construct the polynomial matrix
% by cyclically permuting the rows to the right
% poly_mat = [2 3 1 1]
%            [1 2 3 1]
%            [1 1 2 3]
%            [3 1 1 2]
poly_mat = cycle (rows, 'right');

% Define the first row of the inverse polynomial coefficient matrix
% to be used in INV_MIX_COLUMNS in hexadecimal representation.
inv_row_hex = {'0e' '0b' '0d' '09'};

% Convert the polynomial coefficients to decimal "numbers"
inv_row = hex2dec (inv_row_hex)';

% Construct a matrix with identical rows
inv_rows = repmat (inv_row, 4, 1);

% Construct the polynomial matrix
inv_poly_mat = cycle (inv_rows, 'right');

