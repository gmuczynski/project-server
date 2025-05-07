const express = require('express');
const router = express.Router();
const pool = require('../db'); // Połączenie z bazą danych

router.get('/', async (req, res) => {
    try {
        const [records] = await pool.query('SELECT * FROM police_records'); // Zmień na odpowiednią nazwę tabeli
        res.json(records);
    } catch (error) {
        console.error('Błąd podczas pobierania rekordów:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas pobierania rekordów.' });
    }
});

// Dodaj nowy rekord
router.post('/', async (req, res) => {
    const {
        citizenId,
        name,
        fine,
        jail,
        charges,
        policeofficer,
        comments,
    } = req.body;

    //console.log(req.body)

    try {
        const [result] = await pool.query(
            'INSERT INTO police_records (citizen_char_id, citizen_char_fullname, fine_amount, prison_time, crimes, policeofficer, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [citizenId, name, fine, jail, charges, policeofficer, comments]
        );

        res.status(201).json({ message: 'Rekord został dodany.', id: result.insertId });
    } catch (error) {
        console.error('Błąd podczas dodawania rekordu:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas dodawania rekordu.' });
    }
});

router.delete('/:id', async (req, res) => {
    const recordId = req.params.id;

    try {
        const [result] = await pool.query('DELETE FROM police_records WHERE id = ?', [recordId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Rekord nie został znaleziony.' });
        }

        res.status(200).json({ message: 'Rekord został usunięty.' });
    } catch (error) {
        console.error('Błąd podczas usuwania rekordu:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas usuwania rekordu.' });
    }
});

module.exports = router;