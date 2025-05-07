const express = require('express');
const router = express.Router();
const pool = require('../db'); // Połączenie z bazą danych

// Endpoint do pobierania danych obywatela
router.get('/:id', async (req, res) => {
    const citizenId = req.params.id;

    try {
        const [resultCitizen] = await pool.query(
            'SELECT * FROM characters WHERE id = ?',
            [citizenId]
        );

        const [resultVehicles] = await pool.query(
            'SELECT * FROM vehicles WHERE owner_char_id = ?',
            [citizenId]
        );

        const [resultWanted] = await pool.query(
            'SELECT * FROM police_poszukiwane_osoby WHERE poszukiwany_char_id = ?',
            [citizenId]
        )

        const [resultNotes] = await pool.query(
            'SELECT * FROM police_citizen_notes WHERE character_id = ? AND is_deleted = 0',
            [citizenId]
        )


        if (resultCitizen.length === 0) {
            console.log('Nie znaleziono obywatela');
            return res.status(404).json({ error: 'Obywatel nie został znaleziony' });
        }

        console.log(resultWanted)

        const citizen = resultCitizen[0];

        const data = {
                id: citizen.id,
                char_fullname: citizen.char_fullname,
                char_birthdate: citizen.char_birthdate,
                char_height: citizen.char_height,
                char_licenses: citizen.char_licenses,
                citizen_vehicles: resultVehicles,
                citizen_properties: [],
                citizen_notes: resultNotes,
                isWanted: resultWanted.length !== 0,
                char_sex: "male",
            }

        res.json(data);
    } catch (error) {
        console.error('Błąd podczas pobierania danych obywatela:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas pobierania danych.' });
    }
});

router.get('/searchbyname/:name', async (req, res) => {
    const nameToSearch = req.params.name;

    try {
        const [result] = await pool.query(
            `SELECT id, char_fullname, char_birthdate, char_sex FROM characters WHERE char_fullname LIKE '%${nameToSearch}%'`
        );


        if (result.length === 0) {
            console.log('Nie znaleziono obywateli');
            return res.status(404).json({ error: 'Obywatel nie został znaleziony' });
        }

        res.send(result)
    } catch (error) {
        console.error('Błąd podczas pobierania danych obywatela:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas pobierania danych.' });
    }
});

module.exports = router;
