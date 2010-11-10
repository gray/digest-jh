use strict;
use warnings;
use Test::More tests => 68;
use Digest::JH qw(jh_256 jh_256_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::JH->new(256)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            jh_256_hex($data), $digest,
            "jh_256_hex: $len bits of $msg"
        );
        ok(
            jh_256($data) eq pack('H*', $digest),
            "jh_256: $len bits of $msg"
        );
    }

    my $md = Digest::JH->new(256)->add_bits($data, $len)->hexdigest;
    is($md, $digest, "new/add_bits/hexdigest: $msg");
}
continue { $len++ }

__DATA__
00|020CDD61951FDCADCC544096176332B213B4604AC42DFA82026B7CD750A0A90B
00|5819237F9CF57C77B3AC792A3E4C0C2841FD1F4E2B5BA1EC8ACA27B089642085
C0|96765620CD2334B44430F87BE23C9869F8DB50FBD79E3834B9766BAEA2DA5747
C0|BEDF615A5CA2FA10528F13B9284C4707F30291BB01F017DC8E334375B85D9E13
80|30F08EDD91BB2A30C5EBB8F429E2E6B13A6A2D05F7498B7437CC995C7A2EE142
48|F1DC4971965745FE79091B4CC5339D9978B92A36372AE1B471F94853125DE3DC
50|C6F696BB65DE0DDEF732B6FDFCF1D5581C076AA592DA83D0096076065F7900E8
98|B0404AA8DF78CB0731F009E0565DF1BCEDC86EA86E8376555748CB02E8D5EEA7
CC|AECDD3880991AAE8FEEF92A4171B24953124370158D5EBD29089E849F5604357
9800|F5EBFBB4B3B7AD138CB06D71DB3D2B859C1D93E5C26048E252C05B4BB2F21957
9D40|B506371C00316DD78FBDC4DBBB8F86958E6AD7FEACB3EE96B3139A38F6E6558D
AA80|404431B23662675C190AA8DD05C0CDC5FE4BFE78F111FAE8BF6E0227A63110C9
9830|04639613D69B69CCA52D0B6C9A6D6CD550F11B44A1A9C110BA860CD36AF47555
5030|38EB5535409382214372CF0A26082D8B79AA4F4EA7F723BCFD9A69273FF3A4B7
4D24|5810689E5C62D892FDF0B96842D56BBF12EE16C253C0FDBB325C0EF505FD2BDC
CBDE|0076C8ADBAB982482B7634D1E4AFFEEFD607D012E4A45605BDD2B3D8FEBFDA96
41FB|87AC81CDC65A878615DC3421DF7874CCC4F0D41A5D599B2F29678365B73FEDBA
4FF400|61A0F85439302D79232BD43A8FE6EBCC6DF99B4851D806C59435D8807FD42FC7
FD0440|A0FE0F10C631566816C77D3DD01BCB5CDFC37986FF704A3ECD69EDF3E4C39AC8
424D00|19798378BF08BDD93B1C64C8589951588F3B78C4DF2A39F3DC0CBB1D02870926
3FDEE0|97B181485E7246B6288ACEBD42D5C3B0FAFD3D98710F94BBCFB7CFAAFA82F29A
335768|A181696C80C71BEFE31951ECD3616A022FACD08A00332301E5968964B1E3E69A
051E7C|3FF393F4681DD53E40C789576004EECF332D10DF1FAD952F23E93E61AC0143D0
717F8C|E0598AED020AE8883AD7787ECF58113690A7B68F159C032E0DEA857EEF41BDEF
1F877C|2CB414F03A02735388CBEC02D04247F4062A4D214DB7133A5353DBCCFD271AF9
EB35CF80|83F3C3BB45EDC32233A2BEBC938ACD3B4156E9AE712169212535D3193662B075
B406C480|12877070600CE3256B7A0148F021D20C4DB967A1BCB3AF51A7397E7B12040538
CEE88040|FC6B2912E37CD49CEF497904670D8A1B049AF9516F01E236AEBC34C7CA744A19
C584DB70|37BE7CE991296648CAC39A012074C250A9945AFBC520B9F9E11F04C7B8C60163
53587BC8|9E8EEE1D434D649859946179CF85DCFD62B8E4B47E65FD9EC6867FB133C869B0
69A305B0|A8F95C79E5E99422C89BAEB31EE941E16D3C8CE1F6444F5EF4646CA6F106DE0C
C9375ECE|E95DF1189CED0F503252912930182F7D88A7CB633D4B2222A901EE0F16C7A72E
C1ECFDFC|B4AABFF07A90F14C309BA02C6961463E58E423B7D323E1A0BF7533DADFFAD5F9
8D73E8A280|7066C9068F9DC40F1500DCF965B504C4BEC09BF5ED362B96DD0C273411952211
06F2522080|52A6AA0403E47646713A3122A8E310B3AB44CE4697FA35EFEBB787C89A9061CD
3EF6C36F20|8E45FC88EB676FBD0D58E427873F81A7AD1C3EA8A43FE23EC5ECABEC10C6956B
0127A1D340|4132FC753CEB897131714AC505DF619E2F0D983DE597B3134392C0AD43001EA3
6A6AB6C210|DACAD0EFB4E89A5F55BFB46BAAA5F8DC9A8A08FC0180C833545E41129CCDF702
AF3175E160|2CC55ABBFE19C8FA1E8E54135EB65B77FB928AEAB1BF5CEBEC22F00FFEE7163C
B66609ED86|F9123C31CD99233CC9ADBD7729B0C80044B9F51D158108281E739F1796BFE1D7
21F134AC57|31B47C2E9CFA020D232FCB21806511672F39AF8D19AB2BDB00D4FFA54269509D
3DC2AADFFC80|212E950E6F77D0D04FE1119EA11F835A0B1C030A3E55D6558022A74347093439
9202736D2240|49CC2557FB569793B3279FF5A31EAE278F2E91CCD1465D563122D7C6BE4DBDD0
F219BD629820|63681910751D4647D6450B057EF9F1D35F20E79058FE217F46333DD8FAD1B931
F3511EE2C4B0|8D49E6D93877563FB12FC9D68599C0FD82608934638ABEAC69FEFCF67F22FECC
3ECAB6BF7720|9FFB28DE142CCEDF6E65FEF9477CFA2F21AF02414B0BFC37452666451B3E995C
CD62F688F498|2DD6B20872E97D947FA1838062DCE48D6A4381DFE76E55FA95550212A17EACB6
C2CBAA33A9F8|65F0F4B6A71889A65F536ECB454DC5C76995E6F2ADC8D4D28AC079E283B6C74F
C6F50BB74E29|9619080431B1324C45F695882088F457F6DF45BE5DD4F4CF20F6EB6974C53C14
79F1B4CCC62A00|ECC47C9DA10FBB5524FA31556EB5F66CACF21667BF2FA4ED72EF08FD728FB8BC
