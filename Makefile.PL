use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'GooglePay::PaymentToken',
    VERSION_FROM    => 'lib/GooglePay/PaymentToken.pm',
    AUTHOR          => 'Asyakin Andrey <asan999@gmail.com>',
    PREREQ_PM       => {
        CryptX          => 0,
        JSON::XS        => 0,
        common::sense   => 0,
    },
    TEST_REQUIRES   => {
        'Test::More'  => 0,
    },
);

