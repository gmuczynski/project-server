const express = require('express');
const router = express.Router();
const pool = require('../db'); // Połączenie z bazą danych

router.get('/:plate', async (req, res) => {
    const vehPlate = req.params.plate;

    try {
        const [resultVehicles] = await pool.query(
            'SELECT *, ' +
            '    pwv.vehicle_id IS NOT NULL AS isWanted,\n' +
            '    v.police_vehicle_notes AS notes,\n' +
            '    c.char_fullname AS ownerFullname,\n' +
            '    c.id AS ownerUID\n' +
            'FROM vehicles v\n' +
            'JOIN characters c ON v.owner_char_id = c.id\n' +
            'LEFT JOIN police_wanted_vehicles pwv ON v.id = pwv.vehicle_id\n' +
            'WHERE v.plate = ?',
            [vehPlate]
        );

        const vehicle = resultVehicles[0];

        const ret = {
            owner_id: vehicle.ownerUID,
            owner_fullname: vehicle.char_fullname,
            model: vehicle.model,
            modelLabel: "",
            manufacturerLabel: "",
            plate: vehicle.plate,
            isStolen: false,
            isAllowedInTraffic: true,
            isInsurenceValid: true,
            isWanted: vehicle.isWanted !== 0,
            notes: vehicle.police_vehicle_notes
        }

        res.json(ret)
    } catch (error) {
        console.error('Błąd podczas pobierania danych pojazdu:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas pobierania danych.' });
    }
})

router.get('/id/:id', async (req, res) => {
    const id = req.params.id;

    try {
        const [resultVehicles] = await pool.query(
            'SELECT *, ' +
            '    pwv.vehicle_id IS NOT NULL AS isWanted,\n' +
            '    v.police_vehicle_notes AS notes,\n' +
            '    c.char_fullname AS ownerFullname,\n' +
            '    c.id AS ownerUID\n' +
            'FROM vehicles v\n' +
            'JOIN characters c ON v.owner_char_id = c.id\n' +
            'LEFT JOIN police_wanted_vehicles pwv ON v.id = pwv.vehicle_id\n' +
            'WHERE v.id = ?',
            [id]
        );

        const vehicle = resultVehicles[0];

        const ret = {
            owner_id: vehicle.ownerUID,
            owner_fullname: vehicle.char_fullname,
            model: vehicle.model,
            modelLabel: "",
            manufacturerLabel: "",
            plate: vehicle.plate,
            isStolen: false,
            isAllowedInTraffic: true,
            isInsurenceValid: true,
            isWanted: vehicle.isWanted !== 0,
            notes: vehicle.police_vehicle_notes
        }

        res.json(ret)
    } catch (error) {
        console.error('Błąd podczas pobierania danych pojazdu:', error);
        res.status(500).json({ error: 'Wystąpił błąd podczas pobierania danych.' });
    }
})

module.exports = router;