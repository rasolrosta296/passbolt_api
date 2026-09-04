<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Cryptography;

use App\Utility\OpenPGP\OpenPGPBackendFactory;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use SensitiveParameter;
use Throwable;

final class OpenPgpEnrollmentProofVerifier
{
    use LocatorAwareTrait;

    /**
     * Verify enrollment ownership with the user's registered OpenPGP key.
     */
    public function verify(
        string $userId,
        string $fingerprint,
        string $transcript,
        #[SensitiveParameter]
        string $armoredSignedTranscript
    ): void {
        if (preg_match('/^[0-9A-F]{40}$/D', $fingerprint) !== 1 || strlen($armoredSignedTranscript) > 32_768) {
            throw new CryptoSsoException('openpgp_enrollment_proof_invalid');
        }
        $gpgkey = $this->fetchTable('Gpgkeys')->find()->where([
            'user_id' => $userId,
            'fingerprint' => $fingerprint,
            'deleted' => false,
        ])->first();
        if ($gpgkey === null) {
            throw new CryptoSsoException('openpgp_fingerprint_mismatch');
        }
        $gpg = OpenPGPBackendFactory::get();
        try {
            if (!$gpg->isKeyInKeyring($fingerprint)) {
                $imported = $gpg->importKeyIntoKeyring((string)$gpgkey->get('armored_key'));
                if (!hash_equals($fingerprint, $imported)) {
                    throw new CryptoSsoException('openpgp_fingerprint_mismatch');
                }
            }
            $gpg->setVerifyKeyFromFingerprint($fingerprint);
            $plaintext = null;
            $gpg->verify($armoredSignedTranscript, $plaintext);
        } catch (Throwable $exception) {
            if ($exception instanceof CryptoSsoException) {
                throw $exception;
            }
            throw new CryptoSsoException('openpgp_enrollment_proof_invalid');
        }
        $expected = rtrim(strtr(base64_encode($transcript), '+/', '-_'), '=');
        if (!is_string($plaintext) || !hash_equals($expected, rtrim($plaintext, "\r\n"))) {
            throw new CryptoSsoException('openpgp_enrollment_transcript_mismatch');
        }
    }
}
