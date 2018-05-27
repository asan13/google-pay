use common::sense;

use Test::More;

use GooglePay::PaymentToken;

is( pack('(V/a)*', qw/foo bar baz/), 
    GooglePay::PaymentToken->_signing_string(qw/foo bar baz/),
    'form signature string'
);

my $token = GooglePay::PaymentToken->new(
    private_key => private_key(),
    signing_key => google_public_key_ECv1(),
    merchant_id => '12345678901234567890',
    token       => token(),
);

is_deeply( $token->decrypt_message,
    {       
        messageId => 'AH2EjtfdYYnpR1Qllak2fZRNOTMS96I3IgQfK7vOMV1SIP9pbhO_NhK12xMx7MLEicfiTpRTqgXg8OjYC5hUu6_Hd59uC6JhbrcBk509p1ZbAyOVPI6otJk9ENreC7lo3a4GYsqg7eLp',
        paymentMethodDetails => {
            dpan => '5204240250197840',
            authMethod => '3DS',
            '3dsCryptogram' => 'ALnt+yWSJdXBACMLLWMNGgADFA==',
            expirationYear => 2023,
            expirationMonth => 12
        },
        messageExpiration => '1527972327899',
        paymentMethod     => 'TOKENIZED_CARD'
    },
    'decrypt message'
);


sub private_key {
    '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJW14YggPCrxUXS+YA3TfkjqUTZFW9r3Gpds99wJEjRuoAoGCCqGSM49
AwEHoUQDQgAETs9KCFHe8hHszBQz6XO2FEj0vGbJ6OtaYAS81snrzzJ6qHhvY87B
Q1zgGRR4oa5X0yanDldqUyToKcWyAZQj9g==
-----END EC PRIVATE KEY-----';
}

sub google_public_key_ECv1 {
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX\/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4\/A=='
}

sub token {
    +{
        protocolVersion => 'ECv1',
        signature => 'MEUCIQCnOjENNnxtl7VgKY/SUXmyUDkpenWCJ2EwktGAQloQJgIgO8+1/Nc8ZSYkpVFhkkkaSP8x+10/8ouxp1Cu3Jm9jPc=',
        signedMessage => qq({\"encryptedMessage\":\"yXd+RgRaiTDTXxa42wf2vzD3NTUU135mMUTZLQRQiYZ7gOKlvCCVCJ0mB56b1ye8SIbhU19N3gxgiyATGq9I6Bb4OTDtbVsUH+BDwdJEd2hQfAj3sZDm1XdZS2qKJUJsaMxA0c1k27CJKjeIsGeOTrMEMVv23fMfw7mScJVWaYwf5wVHt3ja2/cv0YvWSSvxlmVLlweySQizuQiZyVOIeCqCXoqeOpwPtj/778LXIM0H8vYJn4pSXKdFqvdn4jMMPc+m3xkNs0HClbfsq2Lroj2SEcyngnYz6CbpnltPwRG6Jmn0Mfss8mrOT5/zSLo2QUUktZWIZrTRE7P7HCV8YvAc/0eTvHeX+rwq5Tsk+e/ZbUolmfy3/ApqY4joaq7BIrBWOAxAKp424SfPirXtNJFEstorWj0s9XWnUgeOunRFasnTf6nC8scTkqpmDvInJORPVWqG/2O1rb5q2KkgBNmNX4AeIgxI+gY0VmLs7DozpgGB0RC8GOTKxnWN00KAA/cBaojRmpVoLgQ\\u003d\",\"ephemeralPublicKey\":\"BJn5SWBdFrLV7Z5pOfsCbSegPJ0k/OlL1Ub5uc8lDaBDm80dhBLIkz6Qqksw0pDVO2jdCooxGEYXCe0FKaKj1YE\\u003d\",\"tag\":\"ztTABIfdRHgtMEWzXPaS1WL3/9GC5MUyJOJ65ydTbgE\\u003d\"}),
    }
}


done_testing;
