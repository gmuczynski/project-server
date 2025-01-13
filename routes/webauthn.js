const express = require('express');
const { generateAuthenticationOptions, verifyAuthenticationResponse, generateRegistrationOptions,
    verifyRegistrationResponse
} = require('@simplewebauthn/server');
const pool = require('../db');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const {raw} = require("mysql2");

const sessions = {}; // Przechowywanie wyzwań w pamięci

// Endpoint do generowania opcji logowania
router.get('/login-options', async (req, res) => {
    try {
        // Pobierz użytkownika z bazy danych
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', ['Gregology']);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Użytkownik nie istnieje' });
        }

        const user = users[0];
        //console.log(user);

        // Pobierz poświadczenia użytkownika
        const [credentials] = await pool.query('SELECT * FROM credentials WHERE user_id = ?', [user.id]);

        const options = generateAuthenticationOptions({
            allowCredentials: credentials.map((cred) => ({
                id: Buffer.from(cred.credential_id, 'base64'),
                type: 'public-key',
            })),
            userVerification: 'preferred',
        });

        // Zapisz wyzwanie w sesji
        sessions.challenge = options.challenge;

        res.json(await options);
    } catch (error) {
        console.error('Błąd podczas generowania opcji logowania:', error);
        res.status(500).json({ error: 'Wystąpił błąd serwera.' });
    }
});

// Endpoint do weryfikacji danych logowania
router.post('/verify', async (req, res) => {
    const { id, response } = req.body;

    try {
        // Pobierz poświadczenie z bazy danych
        const [credentials] = await pool.query('SELECT * FROM credentials WHERE credential_id = ?', [id]);
        if (credentials.length === 0) {
            return res.status(404).json({ error: 'Poświadczenie nie istnieje.' });
        }

        const credential = credentials[0];

        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge: sessions.challenge,
            expectedOrigin: 'http://localhost:3001',
            expectedRPID: 'localhost',
            authenticator: {
                credentialPublicKey: Buffer.from(credential.public_key, 'base64'),
                counter: credential.counter,
            },
        });

        if (verification.verified) {
            // Zaktualizuj licznik w bazie danych
            await pool.query('UPDATE credentials SET counter = ? WHERE id = ?', [
                verification.authenticationInfo.newCounter,
                credential.id,
            ]);

            res.json({ success: true });
        } else {
            res.status(401).json({ error: 'Weryfikacja nie powiodła się.' });
        }
    } catch (error) {
        console.error('Błąd podczas weryfikacji logowania:', error);
        res.status(500).json({ error: 'Wystąpił błąd serwera.' });
    }
});

router.post('/register-options', async (req, res) => {
    const { username } = req.body;

    try {
        // Sprawdź, czy użytkownik już istnieje w bazie danych
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [
            username,
        ]);

        if (users.length > 0) {
            return res.status(400).json({ error: 'Użytkownik już istnieje.' });
        }

        // Generowanie unikalnego identyfikatora użytkownika
        const userId = crypto.randomBytes(16); // Generuje 16 bajtów losowego identyfikatora

        // Tworzenie opcji rejestracji
        const options = generateRegistrationOptions({
            rpName: 'LSPD Database',
            rpID: 'localhost',
            userID: userId, // Tablica bajtów zamiast ciągu znaków
            userName: username, // Nazwa użytkownika
            userDisplayName: username, // Wyświetlana nazwa użytkownika
            attestationType: 'none', // Bez przesyłania attestation do backendu
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // Algorytmy kluczy
        });

        //console.log(await options)

        // Przechowaj wyzwanie i identyfikator użytkownika w sesji
        sessions[username] = {
            challenge: toBase64UrlSafe((await options).challenge),
            userId: userId.toString('base64'), // Zachowaj identyfikator w formacie Base64
        };

        // Zwróć opcje rejestracji do frontend
        res.json(await options);
    } catch (error) {
        console.error('Błąd podczas generowania opcji rejestracji:', error);
        res.status(500).json({ error: 'Wystąpił błąd serwera.' });
    }
});


router.post('/register-verify', async (req, res) => {
    const { id, rawId, type, response } = req.body;

    // Sprawdź, czy wszystkie wymagane dane są obecne
    if (!id || !rawId || !response) {
        return res.status(400).json({ error: 'Missing credential data' });
    }


    const session = Object.values(sessions).find((s) => {
        const clientData = decodeClientDataJSON(response.clientDataJSON);
        return s.challenge === clientData.challenge;
    });

    if (!session) {
        return res.status(400).json({ error: 'Nieprawidłowe wyzwanie.' });
    }

    console.log(id, rawId)

    const verification = await verifyRegistrationResponse({
        response: {
            id,
            rawId,
            response: {
                attestationObject: Buffer.from(response.attestationObject, 'base64'),
                clientDataJSON: Buffer.from(response.clientDataJSON, 'base64'),
            },
            type,
        },
        expectedChallenge: session.challenge,
        expectedOrigin: 'http://localhost:5173',
        expectedRPID: 'localhost',
    });


    console.log(verification)

    if (verification.verified) {
        await pool.query(
            'INSERT INTO credentials (user_id, credential_id, public_key, counter) VALUES (?, ?, ?, ?)',
            [session.userId, id, response.attestationObject, 0]
        );

        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Weryfikacja nie powiodła się.' });
    }
});

function toBase64UrlSafe(buffer) {
    return buffer
        .toString('base64')
        .replace(/\+/g, '-') // Zamiana "+" na "-"
        .replace(/\//g, '_') // Zamiana "/" na "_"
        .replace(/=+$/, ''); // Usuwanie paddingu "="
}

function decodeClientDataJSON(clientDataJSON) {
    const decoded = Buffer.from(clientDataJSON, 'base64').toString('utf-8'); // Dekodowanie Base64
    return JSON.parse(decoded); // Parsowanie JSON
}

function fromBase64UrlSafe(base64UrlSafe) {
    return Buffer.from(
        base64UrlSafe.replace(/-/g, '+').replace(/_/g, '/'),
        'base64'
    );
}


module.exports = router;
