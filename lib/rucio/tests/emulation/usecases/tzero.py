# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Luc Goossens, <luc.goossens@cern.ch>, 2013

'''
tzero use case:
#(1)every 600 seconds do :
#(2)        for each dataset that has new files to upload into DQ2 do :
#(3)             dq2-register -a -x -C -L ... -m <file with data of new files> <DSN> [#calls = O(1500/day), on avg. 30 files per call O(40K/day)]
#(4)             if there will be no more files arriving for this dataset do:
#(5)                    dq2-freeze-dataset -x <DSN> [#calls = O(200/day)]
'''

import random
import time

from datetime import date

from rucio.client import Client
from rucio.common.utils import generate_uuid as uuid
from rucio.tests.emulation.ucemulator import UCEmulator


class UseCaseDefinition(UCEmulator):
    """
        Implements all TZero use cases.
    """
    def EMULATION_RUN_input(self, ctx):
        ctx.runnumber += 1
        return {'interval': ctx.interval,
                'filescale': ctx.filescale,
                'dataXX': ctx.dataXX,
                'runnumber': ctx.runnumber - 1,
                'runspertag': ctx.runspertag,
                'calibfraction': ctx.calibfraction,
                'timespan': super(UseCaseDefinition, self).get_intervals()['EMULATION_RUN']
                }

    def setup(self, ctx):
        d = date.today()
        ctx.runnumber = long('%02d%02d%02d00' % (d.year - 2000, d.month, d.day))
        used_runnnumbers = Client().list_values('run_number')
        print used_runnnumbers
        while unicode(ctx.runnumber) in used_runnnumbers:
            ctx.runnumber += 1
        print 'TZeros starts with runnumber offset: %s' % ctx.runnumber

    @UCEmulator.UseCase
    def EMULATION_RUN(self, interval, filescale, dataXX, runnumber, runspertag, calibfraction, timespan):
        client = Client()
        # Initializing run data
        if random.random() > calibfraction:
            print 'Starting calibration run no. %s' % runnumber
            pattern = [('data12_8TeV.NNNNNNNN.calibration_LArCellsEmpty.daq.RAW', 36),
                       #('data12_8TeV.NNNNNNNN.calibration_Tile.daq.RAW', 36),
                       #('data12_8TeV.NNNNNNNN.calibration_lucid.daq.RAW', 6),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.AOD.f1_m4', 11),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.AOD.x1_m4', 11),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.HIST.f1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.NTUP_BKGD.x1_m2', 7),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.NTUP_SCT.f1_m2', 7),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.RAW', 208),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.TAG.f1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.recon.ESD.f1', 208),
                       #('data12_8TeV.NNNNNNNN.physics_Background.recon.ESD.x1', 208),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.AOD.f1_m4', 11),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.AOD.x1_m4', 11),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.HIST.f1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.RAW', 205),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.TAG.f1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.recon.ESD.f1', 205),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.recon.ESD.x1', 205),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.AOD.x1_m4', 11),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.RAW', 207),
                       ('data12_8TeV.NNNNNNNN.physics_Standby.merge.TAG.x1_m4_m3', 1),
                       ('data12_8TeV.NNNNNNNN.physics_Standby.recon.ESD.x1', 207),
                       ]
        else:
            print 'Starting data run no. %s' % runnumber
            pattern = [('data12_8TeV.NNNNNNNN.calibration_IDTracks.daq.RAW', 141),
                       ('data12_8TeV.NNNNNNNN.calibration_LArCells.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_LArCellsEmpty.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelBeam.daq.RAW', 106),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelBeam.merge.AOD.c819_m4', 66),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelBeam.merge.NTUP_IDVTXLUMI.c819_m2', 10),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelBeam.merge.TAG.c819_m4_m3', 2),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelBeam.recon.ESD.c819', 271),
                       #('data12_8TeV.NNNNNNNN.calibration_PixelNoise.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_SCTNoise.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_Tile.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_beamspot.daq.RAW', 63),
                       #('data12_8TeV.NNNNNNNN.calibration_lucid.daq.RAW', 10),
                       #('data12_8TeV.NNNNNNNN.debug_all.daq.RAW', 4),
                       #('data12_8TeV.NNNNNNNN.debugrec_hltacc.merge.AOD.g1_f2_m4', 1),
                       #('data12_8TeV.NNNNNNNN.debugrec_hltacc.merge.NTUP_FASTMON.g1_f2_m4_m8', 1),
                       #('data12_8TeV.NNNNNNNN.debugrec_hltacc.merge.RAW.g1', 1),
                       #('data12_8TeV.NNNNNNNN.debugrec_hltacc.merge.TAG.g1_f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.debugrec_hltacc.recon.ESD.g1_f2', 1),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.AOD.f2_m4', 21),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.AOD.x1_m4', 21),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.NTUP_SCT.f2_m2', 31),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.NTUP_TRIG.x1_m2', 121),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.RAW', 402),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.TAG.f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.express_express.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.express_express.recon.ESD.f2', 402),
                       #('data12_8TeV.NNNNNNNN.express_express.recon.ESD.x1', 3614),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.AOD.f2_m4', 22),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.AOD.x1_m4', 22),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.NTUP_BKGD.x1_m2', 15),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.NTUP_SCT.f2_m2', 15),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.RAW', 429),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.TAG.f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Background.recon.ESD.f2', 429),
                       #('data12_8TeV.NNNNNNNN.physics_Background.recon.ESD.x1', 429),
                       #('data12_8TeV.NNNNNNNN.physics_Bphysics.merge.RAW', 3150),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.AOD.f2_m4', 22),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.AOD.x1_m4', 22),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.RAW', 425),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.TAG.f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.recon.ESD.f2', 425),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicCalo.recon.ESD.x1', 425),
                       #('data12_8TeV.NNNNNNNN.physics_CosmicMuons.merge.RAW', 399),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.AOD.f2_m4', 312),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.DESDM_EGAMMA.f2_m6', 31),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.DESDM_RPVLL.f2_m6', 21),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.DESD_PHOJET.f2_m6', 74),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.DESD_SGLEL.f2_m6', 57),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.DRAW_ZEE.f2_m9', 37),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.NTUP_FASTMON.f2_m4_m8', 18),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.RAW', 3626),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.merge.TAG.f2_m4_m3', 7),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.recon.DAOD_ZEE.f2_m9_f2', 37),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.recon.DESD_ZEE.f2_m9_f2', 37),
                       #('data12_8TeV.NNNNNNNN.physics_Egamma.recon.ESD.f2', 3626),
                       #('data12_8TeV.NNNNNNNN.physics_HadDelayed.merge.RAW', 3215),
                       #('data12_8TeV.NNNNNNNN.physics_IDCosmic.merge.RAW', 402),
                       #('data12_8TeV.NNNNNNNN.physics_JetCalibDelayed.merge.RAW', 403),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.AOD.f2_m4', 364),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.DESDM_RPVLL.f2_m6', 150),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.DESDM_TRACK.f2_m6', 25),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.DESD_CALJET.f2_m6', 71),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.NTUP_FASTMON.f2_m4_m8', 27),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.RAW', 3624),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.merge.TAG.f2_m4_m3', 8),
                       #('data12_8TeV.NNNNNNNN.physics_JetTauEtmiss.recon.ESD.f2', 3624),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.merge.AOD.f2_m4', 21),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.merge.DESD_MBIAS.f2_m6', 24),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.merge.RAW', 403),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.merge.TAG.f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_MinBias.recon.ESD.f2', 403),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.AOD.f2_m4', 334),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.DESDM_RPVLL.f2_m6', 54),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.DESD_SGLMU.f2_m6', 254),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.DRAW_ZMUMU.f2_m9', 47),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.NTUP_FASTMON.f2_m4_m8', 19),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.RAW', 3629),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.merge.TAG.f2_m4_m3', 7),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.recon.DAOD_ZMUMU.f2_m9_f1', 47),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.recon.DESD_ZMUMU.f2_m9_f1', 47),
                       #('data12_8TeV.NNNNNNNN.physics_Muons.recon.ESD.f2', 3629),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.AOD.x1_m4', 2),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.RAW', 24),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_Standby.recon.ESD.x1', 24),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.AOD.f2_m4', 21),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.AOD.x1_m4', 21),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.HIST.f2_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.HIST.x1_m1', 1),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.RAW', 402),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.TAG.f2_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.merge.TAG.x1_m4_m3', 1),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.recon.ESD.f2', 402),
                       #('data12_8TeV.NNNNNNNN.physics_ZeroBias.recon.ESD.x1', 402),
                       ('data12_8TeV.NNNNNNNN.physics_ZeroBiasOverlay.merge.RAW', 404),
                       ('data12_calib.0NNNNNNNN.calibration_MuonAll.daq.RAW', 70),
                       ]

        tz_account = 'tier0'
        tz_group = 'tier0'
        tz_provenance = 'T0'
        tz_rse = 'MOCK3'
        tz_filesize = 2000000000     # 2GB

        factor = runnumber / runspertag
        tagdict = {'x1': 'x%s' % (factor * 1 + 1),
                   'f1': 'f%s' % (factor * 2 + 1),
                   'f2': 'f%s' % (factor * 2 + 2),
                   'm1': 'm%s' % (factor * 10 + 1),
                   'm2': 'm%s' % (factor * 10 + 2),
                   'm3': 'm%s' % (factor * 10 + 3),
                   'm4': 'm%s' % (factor * 10 + 4),
                   'm6': 'm%s' % (factor * 10 + 6),
                   'm8': 'm%s' % (factor * 10 + 8),
                   'm9': 'm%s' % (factor * 10 + 9)
                   }

        # pre compute all datasets
        ds = []
        for n, s in pattern:
            newname = n.replace('data12', dataXX).replace('NNNNNNNN', str(runnumber).zfill(8)) % tagdict
            newscope = newname.split('.')[0]
            newsize = s * filescale
            ds.append([newscope, newname, newsize, 0])  # 0 is initial value of file counter

        # register run number
        client.add_value('run_number', runnumber)

        # open all datasets
        for scope, datasetname, s, c in ds:
            pcs = datasetname.split('.')
            meta = {'project': pcs[0],
                    'stream_name': pcs[2],
                    'prod_step': pcs[3],
                    'datatype': pcs[4],
                    #'version': pcs[5],
                    'guid': uuid(),
                    }
            meta['group'] = tz_group
            meta['provenance'] = tz_provenance
            meta['run_number'] = runnumber
            print 'Creating dataset: %s:%s' % (scope, datasetname)
            self.time_it(fn=client.add_dataset, kwargs={'scope': scope, 'name': datasetname,
                                                        'statuses': {'monotonic': True}, 'meta': meta,
                                                        'rules': [{'account': tz_account, 'copies': 1, 'rse_expression': tz_rse, 'grouping': 'DATASET'}]})  # The missing lifetime attribute indicated an infinite lifetime

        t = 0
        while t < timespan:
            t += interval
            time.sleep(interval)
            for d in ds:
                scope, datasetname, s, c = d
                # calculate target file counter
                target = int(t * s / timespan)
                # cap at dataset size
                target = min(s, target)
                # calculate new files, if any
                if target > c:
                    newfiles = []
                    for i in range(c + 1, target + 1):
                        filename = datasetname + '._' + str(i).zfill(6)
                        onefile = {'name': filename, 'scope': scope, 'bytes': tz_filesize}
                        newfiles.append(onefile)
                    d[3] = target
                    print 'Appending %s files to %s:%s' % (len(newfiles), scope, datasetname)
                    self.time_it(fn=client.add_files_to_dataset, kwargs={'scope': scope, 'name': datasetname, 'files': newfiles, 'rse': tz_rse})

        # close all datasets
        for scope, datasetname, s, c in ds:
            print 'CLose dataset %s:%s' % (scope, datasetname)
            self.time_it(fn=client.close, kwargs={'scope': scope, 'name': datasetname})
