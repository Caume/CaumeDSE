sub cmePERLProcessColumnNames
{
    my (@cn) = @_;
    (@cn);
}

sub cmePERLProcessRow
{
    my (@r) = @_;
    $r[0] = "X" x (1024 * 1024 + 1);
    (@r);
}
