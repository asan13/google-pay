package GooglePay::PaymentToken;
use common::sense;

our $VERSION = '0.02';

=encoding utf8

=head1 Decrypt the payment token

L<Payment data cryptography for merchants|https://developers.google.com/pay/api/web/resources/payment-data-cryptography>

L<Object reference|https://developers.google.com/pay/api/web/reference/object>

=cut


use MIME::Base64 qw(decode_base64);
use Digest::SHA ();
use Crypt::PK::ECC ();
use Crypt::KeyDerivation ();
use Crypt::Mac::HMAC;
use Crypt::Mode::CTR;
use JSON;

use constant {
    GOOGLE_SENDER_ID         => 'Google',
    GOOGLE_TEST_RECIPIENT_ID => '12345678901234567890',
    GOOGLE_CONTEXT_INFO_ECV1 => 'Google',
    CTR_CIPHER               => 'AES',
    CTR_MODE                 => 1,
    CTR_WIDTH                => 128,
};

=head1 Конструктор

Параметры:
 
 private_key    -   Private key.

 signing_key    -   Public key to verify the signature of the message.

 merchant_id    -   Merchant ID. In the test mode Google uses the identifier 
                    "12345678901234567890" when forming the signed string. 

 token          -   Decoded response field paymentMethodToken.token 

=cut

sub new {
    my ($class, %opts) = @_;
    
    my $self;
    $self->{private_key} = $opts{private_key} or die 'private key required';
    $self->{signing_key} = $opts{signing_key} or die 'signing key required';
    $self->{merchant_id} = $opts{merchant_id} or die 'merchant_id required';
    $self->{token}       = $opts{token}       or die 'token required';

    $class->_validate_token($opts{token});

    bless $self, $class;
}

=head1 decrypt_message

Returns the decrypted message.

Example message for the payment method TOKENIZED_CARD::

    {
        paymentMethod        => 'TOKENIZED_CARD',
        messageExpiration    => '1527972327899',
        messageId            => 'AH2EjtfdYY...',
        paymentMethodDetails => {
            dpan            => '5204240250197840',
            authMethod      => '3DS',
            3dsCryptogram   => 'ALnt+yWSJdXBACMLLWMNGgADFA==',
            expirationYear  => 2023,
            expirationMonth => 12
        }
    }

for CARD:

    {                                
        paymentMethod        => 'CARD',
        messageExpiration    => '1527971896184'
        messageId            => 'AH2EjtfC20...',
        paymentMethodDetails => {
            pan             => '4111111111111111',
            expirationMonth => 12,
            expirationYear  => 2023
        }
    }

=cut

sub decrypt_message {
    my $self = shift;

    unless ($self->_verify_signature) {
        die 'signature verification failed';
    }

    my $message = decode_json $self->{token}{signedMessage};

    $self->_validate_message($message);

    my $eph_key = decode_base64 $message->{ephemeralPublicKey};
    my $enc_msg = decode_base64 $message->{encryptedMessage};
    my $tag     = decode_base64 $message->{tag};

    my $shared = $self->_shared_key($eph_key);

    my $hkdf = Crypt::KeyDerivation::hkdf( $eph_key . $shared, 
        "\0"x32, 
        'SHA256', 
        32, 
        GOOGLE_CONTEXT_INFO_ECV1,
    );

    my $symmetric_key = substr $hkdf, 0, 16;
    my $mac           = substr $hkdf, 16, 32;

    my $compute_tag = Crypt::Mac::HMAC::hmac('SHA256', $mac, $enc_msg);
    unless ($self->_verify_tag($compute_tag, $tag)) {
        die 'tag verification failed';
    }

    my $msg = $self->_decrypt($symmetric_key, $enc_msg);

    decode_json $msg;
}   

sub _decrypt {
    my ($self, $key, $enc_msg) = @_;
    my $aes = Crypt::Mode::CTR->new(CTR_CIPHER, CTR_MODE, CTR_WIDTH);
    $aes->start_decrypt($key, "\0"x16);
    $aes->add($enc_msg) . $aes->finish;
}

sub _shared_key {
    my ($self, $eph_key) = @_;

    my $point = substr $eph_key, 1;
    my $ecc_public = {
        pub_x      => join('', unpack 'H*', substr($point, 0, 32)),
        pub_y      => join('', unpack 'H*', substr($point, 32, 32)),
        curve_name => 'nistp256',
    };

    Crypt::PK::ECC::ecc_shared_secret(
        Crypt::PK::ECC->new( \$self->{private_key} ),
        Crypt::PK::ECC->new( $ecc_public ) 
    );
}

sub _validate_token {
    my ($self, $token) = @_;
    for ( qw/signature protocolVersion signedMessage/ ) {
        die "invalid token: $_ field missing" unless $token->{$_};
    }
}

sub _validate_message {
    my ($self, $msg) = @_;
    for ( qw/ephemeralPublicKey encryptedMessage tag/ ) {
        $msg->{$_} or die "invalid message: '$_' field missing";
    }
}

sub _signing_string {
    shift;
    pack '(V/a)*', @_;
}
    
sub _recipient_id {
    'merchant:' . shift->{merchant_id};
}

sub _verify_signature {
    my $self = shift;

    my $message = $self->_signing_string(
        GOOGLE_SENDER_ID,
        $self->_recipient_id,
        $self->{token}{protocolVersion},
        $self->{token}{signedMessage},
    );

    my $signature = decode_base64 $self->{token}{signature};
    my $sign_key  = decode_base64 $self->{signing_key};
    my $ecc = Crypt::PK::ECC->new(\$sign_key);

    $ecc->verify_hash($signature, Digest::SHA::sha256($message));
}

sub _verify_tag {
    my ($self, $tag, $tag2) = @_;

    return 0 unless length $tag == length $tag2;

    my $res = 0;

    for (map unpack('C'), split //, $tag) {
        $res |= $_ ^ unpack 'C', substr $tag2, 0, 1, '';
    }

    return $res == 0 ? 1 : 0;
}

1;
