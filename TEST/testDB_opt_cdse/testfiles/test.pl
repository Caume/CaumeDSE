if ($init eq undef)
{
    print "Global initialization of Perl Script\n";
    $init=1;
    $colsum=0;
    $index=-1;
}
else
{
    $init+=1;
}
print "This is run number ".$init."\n";

sub showtime
{
    print time."\n";
}

sub function
{
     my ($a, $b) = @_;
     print "perl string A: ",$a,"\n";
     print "perl string B: ",$b,"\n";
     ($a."_appended_1\n", $b."_appended_2\n");
}

sub iterate #Simple test for cmeSQLRows()
{
    my (@a) = @_;
    print "PERL sub iterate on array: @a\n";
    $colsum+=@a[3];
    print "current sum = $colsum\n";
    print "PERL sub iterate, result array: @a\n";
    (@a);
}

sub cmePERLProcessRow               #Process a row - Cumulus Engine Iterations
{
    my (@r) = @_;
    print "PERL sub cmePERLProcessRow array: @r\n";
    if ($index >= 0)
    {
        $colsum+=$r[$index];
        $r[$index]=$colsum;  #Accumulate results in this column
    } else {
        print "PERL sub cmePERLProcessRow, no column named - sueldo - found!\n";
    }
    print "current sum = $colsum\n";
    print "PERL sub cmePERLProcessRow, result array: @r\n";
    (@r);
}

sub cmePERLProcessColumnNames       #Get (and optionally modify) column names
{
    $index=-1;   #set index for sum column
    my $cont=0;
    my (@cn) = @_;
    foreach (@cn)
    {
        if ($_ eq "sueldo") #set index.
        {
            $index=$cont;
            print "PERL sub cmePERLProcessColumnNames index for - sueldo - found: $index.\n";
        }
        $cont++;
    }
    print "PERL sub cmePERLProcessColumnNames array: @cn\n";
    print "PERL sub cmePERLProcessColumnNames, result array: @cn\n";
    (@cn);
}
