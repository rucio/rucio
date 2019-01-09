# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Eric Vaandering, <ewv@fnal.gov>, 2018

from __future__ import absolute_import, division, print_function

from nose.tools import assert_raises

from rucio.common.exception import InvalidObject
from rucio.common.schema.cms import validate_schema


# Some tests adapted from https://github.com/dmwm/WMCore/blob/master/test/python/WMCore_t/Lexicon_t.py

class TestSchemaCMS(object):

    def __init__(self):
        pass

    def test_site_names(self):
        """ CMS SCHEMA (COMMON): Test site/RSE names """
        validate_schema('rse', 'T2_US_Nebraska')
        validate_schema('rse', 'T1_US_FNAL_Disk')

        with assert_raises(InvalidObject):
            validate_schema('rse', 'T1_US')
        with assert_raises(InvalidObject):
            validate_schema('rse', 'T1_US_')
        with assert_raises(InvalidObject):
            validate_schema('rse', 'T1_US_FNAL__Disk')
        with assert_raises(InvalidObject):
            validate_schema('rse', 'T2_US_Nebraska-Subpart')

    def test_dids(self):
        """ CMS SCHEMA (COMMON): Test CMS datasets, blocks, and files against DID rules"""

        # Note: The DID validation is necessarily vague because the regex must satisfy CMS dataset, block, and file

        good_ds = [
            "/ZPrimeToTTJets_M500GeV_W5GeV_TuneZ2star_8TeV-madgraph-tauola/StoreResults-Summer12_DR53X-PU_S10_START53_V7A-v1_TLBSM_53x_v3_bugfix_v1/USER",
            "/DoubleMu/aburgmei-Run2012A_22Jan2013_v1_RHembedded_trans1_tau121_ptelec1_17elec2_8_v4/USER"]
        bad_ds = ["/ZPrimeToTTJets/StoreResults|Summer12_DR53X-P",
                  "/_DoubleMu/aburgme/USER1f1eee22-cdee-0f1b-271b-77a7f559e7dd"]
        good_blocks = [
            "/ZPrimeToTTJets_M500GeV_W5GeV_TuneZ2star_8TeV-madgraph-tauola/StoreResults-Summer12_DR53X-PU_S10_START53_V7A-v1_TLBSM_53x_v3_bugfix_v1/USER#620a38a9-29ba-4af4-b650-e2ba07d133f3",
            "/DoubleMu/aburgmei-Run2012A_22Jan2013_v1_RHembedded_trans1_tau121_ptelec1_17elec2_8_v4/USER#1f1eee22-cdee-0f1b-271b-77a7f559e7dd"]
        bad_blocks = ["/ZPrimeToTTJets/StoreResults|Summer12_DR53X-P",
                      "/_DoubleMu/aburgme/USER1f1eee22-cdee-0f1b-271b-77a7f559e7dd"]
        good_lfns = [
            '/store/mc/Fall10/DYToMuMu_M-20_TuneZ2_7TeV-pythia6/AODSIM/START38_V12-v1/0003/C0F3344F-6EC8-DF11-8ED6-E41F13181020.root',
            '/store/mc/2008/2/21/FastSim-CSA07Electron-1203615548/0009/B6E531DD-99E1-DC11-9FEC-001617E30D4A.root',
            '/store/temp/user/ewv/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/temp/user/cinquilli.nocern/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/user/ewv/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/user/cinquilli.nocern/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/temp/group/Exotica/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/group/Exotica/Higgs-123/PrivateSample/v1/1000/a_X-2.root',
            '/store/temp1/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/temp/lustre1/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/backfill/1/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/data/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/data/Run2010A/Cosmics/RECO/v4/000/143/316/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/hidata/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/hidata/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/hidata/HIRun2011/HIMinBiasUPC/RECO/PromptReco-v1/000/182/591/449805F5-7F1B-E111-AC84-E0CB4E55365D.root',
            '/store/t0temp/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/unmerged/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/himc/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/backfill/1/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/backfill/1/t0temp/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/backfill/1/unmerged/data/Run2010A/Cosmics/RECO/v4/000/143/316/0000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/backfill/1/Run2012B/Cosmics/RAW-RECO/PromptSkim-v1/000/194/912/00000/F65F4AFE-14AC-DF11-B3BE-00215E21F32E.root',
            '/store/results/qcd/QCD_Pt80/StoreResults-Summer09-MC_31X_V3_7TeV-Jet30U-JetAODSkim-0a98be42532eba1f0545cc9b086ec3c3/QCD_Pt80/USER/StoreResults-Summer09-MC_31X_V3_7TeV-Jet30U-JetAODSkim-0a98be42532eba1f0545cc9b086ec3c3/0000/C44630AC-C0C7-DE11-AD4E-0019B9CAC0F8.root',  # noqa: E501
            '/store/results/qcd/StoreResults/QCD_Pt_40_2017_14TeV_612_SLHC6_patch1/USER/QCD_Pt_40_2017_14TeV_612_SLHC6_patch1_6be6d116203e430d91d7e1d6d9a88cd7-v1/00000/028DDC2A-63A8-E311-BB40-842B2B5546DE.root',
            '/store/user/fanzago/RelValZMM/FanzagoTutGrid/f30a6bb13f516198b2814e83414acca1/outfile_10_2_tw4.root',
            '/store/group/higgs/SDMu9_Zmumu/Zmumu/OctX_HZZ3lepSkim_SDMu9/1eb161a436e69f7af28d18145e4ce909/3lepSkim_SDMu9_1.root',
            '/store/group/e-gamma_ecal/SDMu9_Zmumu/Zmumu/OctX_HZZ3lepSkim_SDMu9/1eb161a436e69f7af28d18145e4ce909/3lepSkim_SDMu9_1.root',
            '/store/group/B2G/SDMu9_Zmumu/Zmumu/OctX_HZZ3lepSkim_SDMu9/1eb161a436e69f7af28d18145e4ce909/3lepSkim_SDMu9_1.root',
            '/store/group/phys_higgs/meridian/HGGProd/GluGluToHToGG_M-125_8TeV-powheg-pythia6-Summer12-START53_V7D-v2/meridian/GluGlu_HToGG_M-125_8TeV-powheg-LHE_v1/GluGluToHToGG_M-125_8TeV-powheg-pythia6-Summer12-START53_V7D-v2/fb576e5b6a5810681def50b608ec31ad/Hadronizer_TuneZ2star_8TeV_Powheg_pythia_tauola_cff_py_GEN_SIM_DIGI_L1_DIGI2RAW_RAW2DIGI_L1Reco_RECO_PU_1_1_ukQ.root',  # noqa: E501
            '/store/lhe/7365/TprimeTprimeToTHTH_M-400_TuneZ2star_8TeV-madgraph_50219221.lhe',
            '/store/lhe/10860/LQToUE_BetaHalf_vector_YM-MLQ300LG0KG0.lhe.xz',
            '/store/lhe/7365/mysecondary/0001/TprimeTprimeToTHTH_M-400_TuneZ2star_8TeV-madgraph_50219221.lhe',
            '/store/lhe/10860/mysecondary/0001/LQToUE_BetaHalf_vector_YM-MLQ300LG0KG0.lhe.xz',
        ]

        bad_lfns = [
            '/store/temp/lustre/acquisition_;10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/temp/lustre/acquisition_10-A/MuElectron;-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/temp/lustre/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1;/1000/a_X-2.root',
            '/store/temp/lustre/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X;-2.root',
            '/store/temp/acquisition_;10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/temp/acquisition_10-A/MuElectron;-10_100/RAW-RECO/vX-1/1000/a_X-2.root',
            '/store/temp/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1;/1000/a_X-2.root',
            '/store/temp/acquisition_10-A/MuElectron-10_100/RAW-RECO/vX-1/1000/a_X;-2.root',
            '/store/temp/user/ewv/Higgs-123/Private;Sample/v1/a_X-2.root',
            '/store/temp/user/ewv/Higgs-123/PrivateSample/v1;/a_X-2.root',
            '/store/lhe/10860/11%11/1111/LQToUE_BetaHalf_vector_YM-MLQ300LG0KG0.lhe.xz',
        ]

        for ds in good_ds:
            validate_schema('did', {'name': ds, 'scope': 'cms'})
        for ds in bad_ds:
            with assert_raises(InvalidObject):
                validate_schema('did', {'name': ds, 'scope': 'cms'})

        for block in good_blocks:
            validate_schema('did', {'name': block, 'scope': 'cms'})
        for block in bad_blocks:
            with assert_raises(InvalidObject):
                validate_schema('did', {'name': block, 'scope': 'cms'})

        for lfn in good_lfns:
            validate_schema('did', {'name': lfn, 'scope': 'cms'})
        for lfn in bad_lfns:
            with assert_raises(InvalidObject):
                print("Checking %s" % lfn)
                validate_schema('did', {'name': lfn, 'scope': 'cms'})

    def test_scopes(self):
        """ CMS SCHEMA (COMMON): Test CMS scopes"""
        validate_schema('scope', 'cms')
        validate_schema('scope', 'user.ewv')
        validate_schema('scope', 'user.ewv2')
        validate_schema('scope', 'user.e.vaandering')
        with assert_raises(InvalidObject):
            validate_schema('scope', 'user.e-vaandering')  # Has '-'
        with assert_raises(InvalidObject):
            validate_schema('scope', 'user.e01234567890123456789')  # Too long
        with assert_raises(InvalidObject):
            validate_schema('scope', 'higgs')  # Not user.higgs
        with assert_raises(InvalidObject):
            validate_schema('scope', 'csm')  # Anagram

    def test_attachment(self):
        """ CMS SCHEMA (COMMON): Test CMS attachment"""

        # no need to re-test did pattrens
        dids = [{
            'scope': 'cms', 'name': '/store/mc/Fall10/DYToMuMu_M-20_TuneZ2_7TeV-pythia6/AODSIM/START38_V12-v1/0003/C0F3344F-6EC8-DF11-8ED6-E41F13181020.root'
        }]

        dataset = '/DoubleMu/aburgmei-Run2012A_22Jan2013_v1_RHembedded_trans1_tau121_ptelec1_17elec2_8_v4/USER#1f1eee22-cdee-0f1b-271b-77a7f559e7dd'

        scope = 'cms'

        # RSE pattern is defined independently so we want to re-test
        good_rses = [None, 'T2_FR_GRIF_LLR', 'T1_IT_CNAF_Disk']
        bad_rses = ['T2_FR_GRIF-LLR', 'T4_FR_GRIF_LLR']

        with assert_raises(InvalidObject):   # missing dids
            validate_schema('attachment', {'rse': 'T1_FR_CCIN2P3'})

        args = {'dids': dids}
        validate_schema('attachment', args)
        args['scope'] = scope
        args['name'] = dataset
        validate_schema('attachment', args)

        for rse in good_rses:
            args['rse'] = rse
            validate_schema('attachment', args)

        for rse in bad_rses:
            args['rse'] = rse
            with assert_raises(InvalidObject):
                validate_schema('attachment', args)
