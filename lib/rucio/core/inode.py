# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import and_, or_

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import account_exists, get_account
from rucio.core.scope import check_scope
from rucio.db.models1 import Dataset as DATASET
from rucio.db.models1 import DatasetFileAssociation as DATASETCONTENTS
from rucio.db.models1 import Inode as INODE
from rucio.db.models1 import File as FILE
from rucio.db.models1 import InodeType
from rucio.db.session import get_session

session = get_session()

# DATASET FUNCTIONALITY


def register_dataset(scope, datasetName, account, monotonic=False):
    """ create a new dataset.

    :param scope: the namespace where this dataset belongs
    :param datasetName: the name of the dataset to be created
    :param account: the owner who is creating the dataset
    :param monotonic: is set to true then files cannot be removed from dataset
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise InodeNotFound: Inode not found
    :raise DatasetAlreadyExists: a dataset with the same name already exists in the specified scope
    :returns: nothing
    """
    new_inode = INODE()
    new_dataset = DATASET()
    new_inode.update({'scope': scope, 'label': datasetName, 'type': InodeType.DATASET, 'owner': account, 'monotonic': monotonic})
    new_dataset.update({'dsn': datasetName, 'scope': scope, 'owner': account, 'monotonic': monotonic})
    session.add(new_inode)
    session.add(new_dataset)
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_scope(scope):  # Maybe a valid scope does not exist
                raise exception.ScopeNotFound("Scope (%s) does not exist" % scope)
            elif not account_exists(account):  # or non existing account was provided
                raise exception.AccountNotFound("Account (%s) does not exist" % account)
            else:
                raise exception.RucioException(error.args[0])
        elif error.args[0] == "(IntegrityError) columns scope, label are not unique":
            if session.query(INODE).filter_by(scope=scope, label=datasetName).first().type == InodeType.DATASET:
                raise exception.DatasetAlreadyExists('Dataset with same name (%s) already exists in scope (%s)' % (datasetName, scope))
            else:
                raise exception.FileAlreadyExists('Filename with same name (%s) already exists in scope (%s)' % (datasetName, scope))
        elif error.args[0] == "(IntegrityError) columns scope, dsn are not unique":
            raise exception.DatasetAlreadyExists('Dataset with same name (%s) already exists in scope (%s)' % (datasetName, scope))
        else:
            raise exception.RucioException(error.args[0])


def bulk_register_datasets(scope, datasetList, account, skipExisting=None):
    """ register multiple datasets.

    :param account: the owner who is creating the datasets
    :param scope: the namespace where this dataset belongs
    :param datasetList: the name of the dataset to be created
    :param skipExisting: if any dataset already exists, keep going and don't raise an exception
    :raise DatasetAlreadyExists: one of the specified dataset names already exists in the specified scope
    :return: the success state of attempted dataset registrations
    """

    success_states = []

    for dsn in datasetList:
        try:
            register_dataset(scope, dsn, account)
            success_states.append((dsn, 'added'))
        except exception.DatasetAlreadyExists:
            session.rollback()
            if not skipExisting:
                raise
    return success_states


def unregister_dataset(scope, datasetName, account):
    """ unregister a dataset from the system. this functionality is not exposed to users and used only for development purposes.

    :param account: the account searching for the dataset.
    :param scope: the scope where the dataset exists. This parameter is not used to do wildcard matches.
    :param datasetName: the dataset to be removed. This parameter is not used to do wildcard matches.
    """

    dsts = session.query(DATASET)
    inds = session.query(INODE)
    assc = session.query(DATASETCONTENTS)
    try:
        assc.filter_by(scope_dsn=scope, dsn=datasetName).delete()
        dsts.filter_by(scope=scope, dsn=datasetName).delete()
        inds.filter_by(scope=scope, label=datasetName).delete()
    except IntegrityError, error:
        session.rollback()
        raise exception.RucioException(error.args[0])
    inds.filter_by(scope=scope, label=datasetName).delete()
    session.commit()


def does_dataset_exist(datasetScope, datasetName, accountName):
    """ checks to see if dataset exists.

    :param datasetScope: the scope of the dataset. This parameter does not do wildcard searches.
    :param datasetName: the name of the dataset. This parameter does not do wildcard searches.
    :param accountName: the account searching for the dataset.
    """

    datasetScope.replace('*', '%')
    if session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName).first():
        return True
    else:
        return False


def obsolete_dataset(datasetScope, datasetName, accountName):
    """ obsoletes a dataset

   :param datasetScope: the scope of the dataset. The parameter does not do wildcard searches.
   :param datasetName: the name of the dataset. The parameter does not do wildcard searches.
   :param accountName: the account that is requesting this operation.
   :raise DatasetObsolete: dataset is already obsolete
    """

    dsts = session.query(DATASET)
    inds = session.query(INODE)
    cons = session.query(DATASETCONTENTS)
    try:
        dsts.filter_by(scope=datasetScope, dsn=datasetName, obsolete=False).one()
        dsts.filter_by(scope=datasetScope, dsn=datasetName).update({'obsolete': True})
        inds.filter_by(scope=datasetScope, label=datasetName).update({'obsolete': True})
        cons.filter_by(scope_dsn=datasetScope, dsn=datasetName).update({'obsolete': True})
        session.commit()
    except NoResultFound, error:
        session.rollback()
        if is_dataset_obsolete(datasetScope, datasetName, accountName):
            raise exception.DatasetObsolete("Dataset '%s' in scope '%s' already obsolete" % (datasetScope, datasetName))
    except:
        raise exception.RucioException(error.args[0])


def list_datasets(accountName, datasetScope=None, datasetName=None, obsolete=False):
    """ lists datasets matching wildcard search.

    :param accountName: the account searching for the datasets.
    :param datasetScope: the scope where the dataset exists. This parameter accepts wildcards.
    :param datasetName: the list of datasets. This parameter accepts wildcards.
    :param obsolete: by default this api does not list obsolete datasets. If the obsolete option is set as True then api will include obsolete datatasets
    """
    session = get_session()

    if datasetScope is not None:
        datasetScope = datasetScope.replace("*", "%")
    if datasetName is not None:
        datasetName = datasetName.replace("*", "%")

    if datasetScope == '%':
        datasetScope = None
    if datasetName == '%':
        datasetName = None

    # Forbidden searches (commented out as we are now able to track requests we should allow all types of searches)
    #if datasetName is None and datasetScope is None:
    #    raise exception.ForbiddenSearch('Dataset (%s) and scope (%s) wildcard search too broad' % (datasetName, datasetScope))

    dst_query = session.query(DATASET)
    datasets = []
    # No scope
    if datasetScope is None:
        if datasetName is None:  # No dataset defined
            dsts = dst_query.all() if obsolete else dst_query.filter_by(obsolete=False)
        elif '%' not in datasetName:  # No wildcards in dataset name
            dsts = dst_query.filter_by(dsn=datasetName) if obsolete else dst_query.filter_by(dsn=datasetName, obsolete=False)
        else:  # Dataset wild card search
            dsts = dst_query.filter(DATASET.dsn.like(datasetName)) if obsolete else dst_query.filter(DATASET.dsn.like(datasetName)).filter_by(obsolete=False)
    #  Scope has wildcards
    elif '%' in datasetScope:
        if datasetName is None:  # No dataset defined
            dsts = dst_query.filter(DATASET.scope.like(datasetScope)) if obsolete else dst_query.filter(DATASET.scope.like(datasetScope)).filter_by(obsolete=False)
        elif '%' not in datasetName:  # No wildcards in dataset name
            dsts = dst_query.filter(DATASET.scope.like(datasetScope)).filter_by(dsn=datasetName).all() if obsolete else dst_query.filter(DATASET.scope.like(datasetScope)).filter_by(dsn=datasetName, obsolete=False)
        else:  # Dataset wildcard card search
            if obsolete:
                dsts = dst_query.filter(and_(DATASET.scope.like(datasetScope), DATASET.dsn.like(datasetName)))
            else:
                dsts = dst_query.filter(and_(DATASET.scope.like(datasetScope), DATASET.dsn.like(datasetName))).filter_by(obsolete=False)
    # Single scope search
    else:
        if datasetName is None:  # No dataset defined
            dsts = dst_query.filter_by(scope=datasetScope) if obsolete else  dst_query.filter_by(scope=datasetScope, obsolete=False)
        elif '%' not in datasetName:  # No wildcards in dataset name
            if obsolete:
                dsts = dst_query.filter_by(scope=datasetScope, dsn=datasetName)
            else:
                dsts = dst_query.filter_by(scope=datasetScope, dsn=datasetName, obsolete=False)
        else:  # Wildcards in dataset name
            dsts = dst_query.filter_by(scope=datasetScope).filter(DATASET.dsn.like(datasetName)) if obsolete else dst_query.filter_by(scope=datasetScope, obsolete=False).filter(DATASET.dsn.like(datasetName))

    return [dst.dsn for dst in dsts]


def change_dataset_owner(datasetScope, datasetName, oldAccount, newAccount):
    """ Change a dataset's owner

    :param datasetScope: the scope of the dataset
    :param datasetName: the name of the dataset
    :param oldAccount: the owner of the dataset
    :param newAccount: the new owner of the dataset
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise DatasetNotFound: specified dataset does not exist in specified scope
    :raise NotADataset: specified dataset is actually a file
    :raise DatasetObsolete: specified dataset is obsolete
    :raise NoPermissions: specified account is not the owner of the dataset
    """

    try:
        session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName, owner=oldAccount, obsolete=False).one().update({'owner': newAccount})
        session.query(INODE).filter_by(scope=datasetScope, label=datasetName, owner=oldAccount, obsolete=False).one().update({'owner': newAccount})
    except NoResultFound, error:
        session.rollback()
        if not check_scope(datasetScope):  # check that scope exists
            raise exception.ScopeNotFound("Scope (%s) does not exist" % datasetScope)
        elif not account_exists(oldAccount):  # check that account specified exists
            raise exception.AccountNotFound("Account (%s) does not exist" % oldAccount)
        else:  # if account and scope exist then check to see if scope+name are registered as a dataset
            inode_info = get_inode_metadata(datasetScope, datasetName, oldAccount)
            if inode_info is None:
                raise exception.DatasetNotFound("Dataset (%s) does not exist" % datasetName)
            elif inode_info['type'] == InodeType.FILE:  # check if specified dataset is a file
                raise exception.NotADataset("Specified dsn (%s) in scope (%s) is actually a file" % (datasetName, datasetScope))
            elif inode_info['obsolete'] == True:  # check that specified dataset is not obsolete
                raise exception.DatasetObsolete("Dataset (%s) in scope (%s) is obsolete" % (datasetName, datasetScope))
            else:
                raise exception.NoPermissions("Specified account (%s) is not the owner" % oldAccount)
            raise exception.RucioException(error.args[0])
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not account_exists(newAccount):  # check if non existing account was provided
                raise exception.AccountNotFound("Account (%s) does not exist" % newAccount)
            else:
                raise exception.RucioException(error.args[0])
        else:
            raise exception.RucioException(error.args[0])


def get_dataset_metadata(datasetScope, datasetName, account):
    """ Return a dataset's metadata as a dictionary

    :param datasetScope: the scope of the dataset
    :param datasetName: the name of the dataset
    :param account: the account accessing the dataset
    :raise ScopeNotFound: the specified scope does not exist
    :raise DatasetNotFound: the specified dataset does not exist in specified scope
    """

    try:
        dst_info = session.query(INODE).filter_by(scope=datasetScope, label=datasetName, type=InodeType.DATASET).one()
    except NoResultFound, error:
        session.rollback()
        if not check_scope(datasetScope):  # check if non existing account was provided
            raise exception.ScopeNotFound("Scope (%s) does not exist" % datasetScope)
        elif not get_inode_metadata(datasetScope, datasetName, account):
            raise exception.DatasetNotFound("Dataset (%s) does not exist in scope (%s)" % (datasetName, datasetScope))
        else:
            raise exception.RucioException(error.args[0])
    dictionary = {'owner': dst_info.owner, 'obsolete': dst_info.obsolete, 'monotonic': dst_info.monotonic}
    return dictionary


def add_files_to_dataset(inodeList, targetDatasetScope, targetDatasetName, account, inode_scope=None):
    """ Associate a group of files to a dataset. This method accepts a list of inodes, which can be files or datasets. Dataset inodes converted to lists of files. If one the inodes specified is obsolete an exception is raised.

    :param inodeList: A list of inodes defined as (scope, label). If file_scope is defined, then this parameters is a list of labels only
    :param targetDatasetScope: The scope of the dataset which we are adding files to
    :param targetDatasetName: The name of the dataset which we are adding files to
    :param account: The account which is doing this operation
    :param file_scope: Optional parameter for convinience that can be used to specify a inodeList only as a list of names if they have the same scope
    :raise InputValidationError: input parameters failed validation
    :raise NotADataset: specified dataset is actually a file
    :raise DatasetNotFound: target dataset does not exist
    :raise NoPermissions: account is not the owner of the dataset
    :raise InodeNotFound: File or dataset in inodeList does not exist
    """

    # validate inodeList
    if type(inodeList) != list:
        raise exception.InputValidationError("inodeList should be of type 'list'")
    if not inode_scope:
        for inode in inodeList:
            if len(inode) != 2:
                raise exception.InputValidationError('inodeList should have two arguments (scope, name) if inode_scope is not set')
    else:
        for inode in inodeList:
            if type(inode) != str:
                raise exception.InputValidationError("inodeList elect '%s' should be a string" % inode)
    dst_owner = get_dataset_owner(targetDatasetScope, targetDatasetName, account)
    if dst_owner is None:
        if get_inode_type(targetDatasetScope, targetDatasetName, account) == InodeType.FILE:
            raise exception.NotADataset('Specified dataset (%s, %s) is actually a file' % (targetDatasetScope, targetDatasetName))
        else:
            raise exception.DatasetNotFound('Target dataset (%s,%s) does not exist' % (targetDatasetScope, targetDatasetName))
    elif account != dst_owner:
        raise exception.NoPermissions('Files cannot be added to dataset. Account (%s) is not the owner (%s) of the dataset' % (account, dst_owner))
    if inode_scope:
        inodeList = inode_list_generator(inode_scope, inodeList)
    conditions = []
    for inode in inodeList:
        conditions.append(and_(INODE.scope == inode[0], INODE.label == inode[1]))
    db_list = session.query(INODE).filter(or_(*conditions)).all()

    if not len(db_list):  # if nothing returned then one or more parameters are wrong
        for inode in inodeList:
            if not does_inode_exist(inode[0], inode[1], account):
                raise exception.InodeNotFound('File or dataset in inodeList (%s, %s) does not exist' % (inode[0], inode[1]))

    file_list = []
    for target_node in db_list:
        if target_node.type == InodeType.FILE:
            file_list.append((target_node.scope, target_node.label, target_node.scope, target_node.label))
        else:
            for fl in list_files_in_dataset(target_node.scope, target_node.label, account):
                file_list.append((fl[0], fl[1], target_node.scope, target_node.label))

    for file in file_list:
        new_file_association = DATASETCONTENTS()
        new_file_association.update({'scope_dsn': targetDatasetScope, 'dsn': targetDatasetName, 'scope_lfn': file[0], 'lfn': file[1], 'parent_inode_scope': file[2], 'parent_inode_name': file[3]})
        session.add(new_file_association)
        try:
            session.commit()
        except IntegrityError, error:
            session.rollback()
            if error.args[0] == '(IntegrityError) foreign key constraint failed':
                for inode in inodeList:
                    if not does_inode_exist(inode[0], inode[1], account):
                        raise exception.InodeNotFound('File or dataset in inodeList (%s, %s) does not exist' % (inode[0], inode[1]))
            else:
                raise exception.RucioException(error.args[0])


def delete_files_from_dataset(inodeList, targetDatasetScope, targetDatasetName, account):
    """ Delete file associations to specific datasets. This method accepts a list of inodes. If one of the inodes specified is obsolete an expcetion is raised.

    :param inodeList: A list of inodes defined as (scope, label)
    :param targetDatasetScope: The scope of the dataset which we are adding files to
    :param targetDatasetName: The name of the dataset which we are adding files to
    :param force: Will remove files from a dataset even if the dataset is monotonic, this option should not be exposed to users
    :param account: The account which is doing this operation
    :raise NoPermissions: Account is not the owner of the dataset
    :raise DatasetIsMonotonic: The file cannot be removed from the dataset because the dataset is monotonic
    """

    dst_owner = get_dataset_owner(targetDatasetScope, targetDatasetName, account)
    if account != dst_owner:
        raise exception.NoPermissions('Files cannot be removed from dataset. Account (%s) is not the owner (%s) of the dataset' % (account, dst_owner))
    associations = session.query(DATASETCONTENTS)
    if is_dataset_monotonic(targetDatasetScope, targetDatasetName, account):
        raise exception.DatasetIsMonotonic('Target dataset (%s) in scope (%s) is monotonic, removal of file associations is forbidden' % (targetDatasetScope, targetDatasetName))
    for inode in inodeList:
        try:
            associations.filter_by(scope_dsn=targetDatasetScope, dsn=targetDatasetName, scope_lfn=inode[0], lfn=inode[1]).one()
        except NoResultFound, error:
            raise

        associations.filter_by(scope_dsn=targetDatasetScope, dsn=targetDatasetName, scope_lfn=inode[0], lfn=inode[1]).update({'obsolete': True})
    session.commit()


def list_files_in_dataset(datasetScope, datasetName, account):
    """ List files in a dataset. If invalid dataset is provided an exception is raised. If an invalid file is mentioned an exception is raised.

    :param scope: Dataset's scope
    :param dataset: Target dataset
    :param returns: List of files in dataset [ (scope1, filename1), (scope2, filename2), ...]. If dataset is empty, it returns an empty list
    :raise ScopeNotFound: The specified scope does not exist
    :raise DatasetNotFound: The specified dataset does not exist in the specified scope
    """

    files = []
    files_info = session.query(DATASETCONTENTS).filter_by(scope_dsn=datasetScope, dsn=datasetName, obsolete=False).all()
    if not files_info:
        if not check_scope(datasetScope):
            raise exception.ScopeNotFound("Scope (%s) does not exist" % datasetScope)
        elif not does_dataset_exist(datasetScope, datasetName, account):
            raise exception.DatasetNotFound("Dataset (%s) does not exist" % datasetName)
    for file in files_info:
        files.append((file.scope_lfn, file.lfn))
    return files


def is_dataset_monotonic(datasetScope, datasetName, account):
    """ Checks to see if dataset is monotonic.

    :param datasetScope: The scope of the dataset
    :param datasetName: The name of the dataset
    :returns: True if dataset is monotonic, otherwise false. If dataset does not exist the procedure will return None
    :raise ScopeNotFound: The specified scope does not exist
    :raise NotADataset: Specified dataset is actually a file
    :raise DatasetNotFound: The specified dataset does not exist
    """

    try:
        info = session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName).one()
    except  NoResultFound, error:
        __evaluate_no_result_found(datasetScope, datasetName, account, InodeType.DATASET)
    return info.monotonic


def is_dataset_obsolete(datasetScope, datasetName, account):
    """ Check if dataset is obsolete

    :param datasetScope: The scope of the dataset
    :param datasetName: The name of the dataset
    :returns: True if dataset is obsolete, otherwise false. If dataset does not exist the procedure will return None
    :raise ScopeNotFound: The specified scope does not exist
    :raise NotADataset: Specified dataset is actually a file
    :raise DatasetNotFound: The specified dataset does not exist
    """

    try:
        info = session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName).one()
    except NoResultFound, error:
        __evaluate_no_result_found(datasetScope, datasetName, account, InodeType.DATASET)
    return info.obsolete


def __evaluate_no_result_found(inodeScope, inodeName, account, inode_type=None):
    """ Checks to see why no result exception was raised

    :param inodeScope: The scope of the dataset
    :param inodeName: The name of the dataset
    :param account: the account doing the operation
    :raise ScopeNotFound: The specified scope does not exist
    :raise NotADataset: Specified dataset is actually a file
    :raise DatasetNotFound: The specified dataset does not exist
    :raise NotAFile: Specified file is actually a dataset
    :raise FileNotFound: The specified file does not exist
    """

    if not check_scope(inodeScope):
        raise exception.ScopeNotFound("Scope '%s' does not exist" % inodeScope)

    if inode_type == InodeType.DATASET:
        if get_inode_type(inodeScope, inodeName, account) == InodeType.FILE:
            raise exception.NotADataset("Specified dataset (%s, %s) is actually a file" % (inodeScope, inodeName))
        else:
            raise exception.DatasetNotFound('Target dataset (%s) in scope (%s) does not exist.' % (inodeScope, inodeName))
    elif inode_type == InodeType.FILE:
        if get_inode_type(inodeScope, inodeName, account) == InodeType.DATASET:
            raise exception.NotAFile("Specified file (%s, %s) is actually a dataset" % (inodeScope, inodeName))
        else:
            raise exception.FileNotFound('Target file (%s) in scope (%s) does not exist.' % (inodeScope, inodeName))
    elif inode_type == None:
        raise exception.InodeNotFound('Target inode (%s) in scope (%s) does not exist' % (inodeScope, inodeName))
    else:
        exception.InputValidationError('Unrecognised inode type')


def get_dataset_owner(datasetScope, datasetName, account):
    """ Returns the dataset owner

    :param datasetScope: the dataset's scope
    :param datasetName: the dataset's name
    :returns: dataset's owner, None if the dataset does not exist
    :raise ScopeNotFound: The specified scope does not exist
    :raise NotADataset: Specified dataset is actually a file
    :raise DatasetNotFound: The specified dataset does not exist
    """

    try:
        info = session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName).one()
    except:
        __evaluate_no_result_found(datasetScope, datasetName, account, InodeType.DATASET)
    return info.owner

# FILE FUNCTIONALITY


def register_file(scope, filename, account):
    """ register a new dataset.

    :param account: the owner who is creating the file
    :param scope: the namespace where this file belongs
    :param name: the name of the file to be created
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: account does not exist
    :raise DatasetAlreadyExists: Dataset with same name as specified filename already exists
    :raise FileAlreadyExists: File with same name as specified filename already exists
    :returns: nothing
    """

    new_inode = INODE()
    new_file = FILE()
    new_inode.update({'scope': scope, 'label': filename, 'type': InodeType.FILE, 'owner': account})
    new_file.update({'lfn': filename, 'scope': scope, 'owner': account})
    session.add(new_inode)
    session.add(new_file)
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_scope(scope):  # Maybe a valid scope does not exist
                raise exception.ScopeNotFound("Scope (%s) does not exist" % scope)
            elif not account_exists(account):  # If not then maybe a non existing account was specified
                raise exception.AccountNotFound("Account (%s) does not exist" % account)
            else:
                raise exception.RucioException(error.args[0])
        elif error.args[0] == "(IntegrityError) columns scope, label are not unique":
            if session.query(INODE).filter_by(scope=scope, label=filename).first().type == InodeType.DATASET:
                raise exception.DatasetAlreadyExists('Dataset with same name (%s) as specified file already exists in scope (%s)' % (filename, scope))
            else:
                raise exception.FileAlreadyExists('Filename with same name (%s) already exists in scope (%s)' % (filename, scope))
        elif error.args[0] == "(IntegrityError) columns scope, lfn are not unique":
            raise exception.FileAlreadyExists("File '%s' already exists in scope '%s'" % (filename, scope))
        else:
            raise exception.RucioException(error.args[0])


def obsolete_file(fileScope, filename, accountName):
    """ obsoletes a file

   :param fileScope: the scope of the file. The parameter does not do wildcard searches.
   :param filename: the name of the file. The parameter does not do wildcard searches.
   :param accountName: the account that is requesting this operation.
   :raise FileObsolete: file is already obsolete
    """

    fils = session.query(FILE)
    inds = session.query(INODE)
    cons = session.query(DATASETCONTENTS)
    try:
        fils.filter_by(scope=fileScope, lfn=filename, obsolete=False).one()
        fils.filter_by(scope=fileScope, lfn=filename).update({'obsolete': True})
        inds.filter_by(scope=fileScope, label=filename).update({'obsolete': True})
        cons.filter_by(scope_dsn=fileScope, lfn=filename).update({'obsolete': True})
        session.commit()
    except NoResultFound, error:
        session.rollback()
        if is_file_obsolete(fileScope, filename, accountName):
            raise exception.FileObsolete("File '%s' in scope '%s' already obsolete" % (fileScope, filename))
        else:
            raise exception.RucioException(error.args[0])


def is_file_obsolete(fileScope, filename, account):
    """ Check if file is obsolete

    :param fileScope: The scope of the file
    :param filename: The name of the file
    :returns: True if file is obsolete, otherwise false
    :raise ScopeNotFound: The specified scope does not exist
    :raise NotAFile: Specified file is actually a dataset
    :raise FileNotFound: The specified file does not exist
    """

    try:
        info = session.query(FILE).filter_by(scope=fileScope, lfn=filename).one()
    except NoResultFound, error:
        __evaluate_no_result_found(fileScope, filename, account, inode_type=InodeType.FILE)
    return info.obsolete


def bulk_register_files(scope, fileList, account, skipExisting=None):
    """ create new datasets in a single transaction.

    :param account: the owner who is creating the files
    :param scope: the namespace where this files belongs
    :param datasetList: the name of the files to be created
    :param skipExisting: if any file already exists, keep going and don't raise an exception
    :returns success_states of dataset registration
    """

    session = get_session()

    success_states = []
    for lfn in fileList:
        try:
            register_file(scope, lfn, account)
            success_states.append((lfn, 'added'))
        except exception.FileAlreadyExists:
            if not skipExisting:
                raise
    return success_states


def unregister_file(scope, name, account):
    """ unregister a file from the system. this functionality is not exposed to users and used only for development purposes. This method will also remove all file associations to the dataset.

    :param account: the account searching for the dataset.
    :param scope: the scope where the file exists. This parameter is not used to do wildcard matches.
    :param name: the file to be removed. This parameter is not used to do wildcard matches.
    """

    session = get_session()

    fils = session.query(FILE)
    inds = session.query(INODE)
    fils.filter_by(scope=scope, lfn=name).delete()
    inds.filter_by(scope=scope, label=name).delete()
    session.commit()


def does_file_exist(scope, filename, account):
    """ checks to see if dataset exists.

    :param accountName: the account searching for the file.
    :param scope: the scope where the file exists. This parameter does not do wildcard searches.
    :param filename: the name of the file. This parameter does not do wildcard searches.
    """

    session = get_session()

    return True if session.query(FILE).filter_by(scope=scope, lfn=filename).first() else False


def list_files(account, scope=None, filename=None, obsolete=False):
    """ lists files matching wildcard search.

    :param account: the account searching for the files.
    :param scope: the scope of the file. This parameter accepts wildcards.
    :param filename: the list of datasets. This parameter accepts wildcards.
    """
    session = get_session()

    if scope is not None:
        scope = scope.replace("*", "%")
    if filename is not None:
        filename = filename.replace("*", "%")

    if scope == '%':
        scope = None
    if filename == '%':
        filename = None

    # Forbiden searches (commented out as we are now able to track requests we should allow all types of searches)
    #if fileName is None and scope is None:
    #    raise exception.ForbidenSearch('File (%s) and scope (%s) wildcard search too broad' % (filename, scope))

    file_query = session.query(FILE)
    # No scope
    if scope is None:
        if filename is None:  # No dataset defined
            files = file_query.all() if obsolete else file_query.filter_by(obsolete=False)
        elif '%' not in filename:  # No wildcards in dataset name
            files = file_query.filter_by(lfn=filename) if obsolete else file_query.filter_by(lfn=filename, obsolete=False)
        else:  # Dataset wild card search
            files = file_query.filter(FILE.lfn.like(filename)) if obsolete else file_query.filter(FILE.lfn.like(filename)).filter_by(obsolete=False)
    #  Scope has wildcards
    elif '%' in scope:
        if filename is None:  # No dataset defined
            files = file_query.filter(FILE.scope.like(scope)) if obsolete else file_query.filter(FILE.scope.like(scope)).filter_by(obsolete=False)
        elif '%' not in filename:  # No wildcards in dataset name
            files = file_query.filter(FILE.scope.like(scope)).filter_by(lfn=filename).all() if obsolete else file_query.filter(FILE.scope.like(scope)).filter_by(lfn=filename, obsolete=False)
        else:  # Dataset wildcard card search
            files = file_query.filter(FILE.scope.like(scope)).filter(FILE.lfn.like(filename)) if obsolete else file_query.filter(FILE.scope.like(scope)).filter(FILE.lfn.like(filename)).filter_by(obsolete=False)
    # Single scope search
    else:
        if filename is None:  # No dataset defined
            files = file_query.filter_by(scope=scope) if obsolete else file_query.filter_by(scope=scope, obsolete=False)
        elif '%' not in filename:  # No wildcards in dataset name
            files = file_query.filter_by(scope=scope, lfn=filename) if obsolete else file_query.filter_by(scope=scope, lfn=filename, obsolete=False)
        else:  # Wildcards in dataset name
            files = file_query.filter_by(scope=scope).filter(FILE.lfn.like(filename)) if obsolete else file_query.filter_by(scope=scope, obsolete=False).filter(FILE.lfn.like(filename))
    return [file.lfn for file in files]


def change_file_owner(fileScope, filename, oldAccount, newAccount):
    """ Change a file's owner

    :param fileScope: the scope of the file
    :param filename: the name of the file
    :param oldAccount: the owner of the file
    :param newAccount: the new owner of the file
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise FileNotFound: specified filename not found in specified scope
    :raise FileObsolete: specified file is obsolete
    :raise NoPermissions: specified account is not the owner of the file
    """

    try:
        session.query(FILE).filter_by(scope=fileScope, lfn=filename, owner=oldAccount, obsolete=False).one().update({'owner': newAccount})
        session.query(INODE).filter_by(scope=fileScope, label=filename, owner=oldAccount, obsolete=False).one().update({'owner': newAccount})
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(fileScope):  # check that scope exists
                raise exception.ScopeNotFound("Scope (%s) does not exist" % fileScope)
            elif not account_exists(oldAccount):  # check that account specified exists
                raise exception.AccountNotFound("Account (%s) does not exist" % oldAccount)
            else:  # if account and scope exist then check to see if scope+name are registered as a file
                inode_info = get_inode_metadata(fileScope, filename, oldAccount)
                if inode_info is None:
                    raise exception.FileNotFound("File (%s) does not exist" % filename)
                elif inode_info['type'] == InodeType.DATASET:  # check if specified file is actually a dataset
                    raise exception.NotAFile("Specified file (%s) in scope (%s) is actually a dataset" % (filename, fileScope))
                elif inode_info['obsolete'] == True:  # check that specified dataset is not obsolete
                    raise exception.FileObsolete("File (%s) in scope (%s) is obsolete" % (filename, fileScope))
                else:
                    raise exception.NoPermissions("Specified account (%s) is not the owner" % oldAccount)
        else:
            exception.RucioException(error.args[0])
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not account_exists(newAccount):  # check if non existing account was provided
                raise exception.AccountNotFound("Account (%s) does not exist" % newAccount)
            else:
                raise exception.RucioException(error.args[0])
        else:
            raise exception.RucioException(error.args[0])


def get_file_metadata(fileScope, filename, account):
    """ Return a file's metadata as a dictionary

    :param fileScope: the scope of the file
    :param filename: the name of the file
    :param account: the account accessing the file
    :raise ScopeNotFound: specified scope does not exist
    :raise FileNotFound: Specified file does not exist
    """

    try:
        dst_info = session.query(INODE).filter_by(scope=fileScope, label=filename, type=InodeType.FILE).one()
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(fileScope):  # check if non existing account was provided
                raise exception.ScopeNotFound("Scope (%s) does not exist" % fileScope)
            elif not does_file_exist(fileScope, filename, account):
                raise exception.FileNotFound("File (%s) does not exist in scope (%s)" % (filename, fileScope))
            else:
                raise exception.RucioException(error.args[0])
        else:
            raise exception.RucioException(error.args[0])
    dictionary = {'owner': dst_info.owner, 'obsolete': dst_info.obsolete}
    return dictionary


# INODE FUNCTIONALITY


def does_inode_exist(scope, name, account):
    """ checks to see if inode exists.

    :param account: the account searching for the file.
    :param scope: the scope where the inode exists. This parameter does not do wildcard searches.
    :param name: the name of the inode. This parameter does not do wildcard searches.
    :returns: True if inode exists, otherwise False
    """

    return True if session.query(INODE).filter_by(scope=scope, label=name).first() else False


def is_inode_obsolete(scope, name, account):
    """ Check if file is obsolete

    :param scope: The scope of the inode
    :param name: The name of the file
    :returns: True if file is obsolete, otherwise false
    :raise ScopeNotFound: The specified scope does not exist
    :raise InodeNotFound: The specified inode does not exist
    """

    try:
        info = session.query(INODE).filter_by(scope=scope, label=name).one()
    except NoResultFound, error:
        __evaluate_no_result_found(scope, name, account)
    return info.obsolete


def get_inode_metadata(inodeScope, inodeName, account):
    """ Return inode metadata

    :param inodeScope: scope of the file or dataset
    :param inodeName: name of the file or dataset
    :param account: the account making the request
    :returns: inode metadata or None if inode does not exist
    """

    inodeScope.replace('*', '%')
    inode = session.query(INODE).filter_by(scope=inodeScope, label=inodeName).first()
    if not inode:
        return None
    else:
        metadata = {'type': inode.type, 'obsolete': inode.obsolete, 'owner': inode.owner}
        if inode.type == InodeType.DATASET:
            metadata['monotonic'] = inode.monotonic
        return metadata


def get_inode_type(inodeScope, inodeName, account):
    """ Returns the inode's type

    :param inodeScope: scope of the file or dataset
    :param inodeName: name of the file or dataset
    :param account: the account making the request
    :returns: inode metadata or None if inode does not exist
    """

    inode = session.query(INODE).filter_by(scope=inodeScope, label=inodeName).first()
    if not inode:
        return None
    else:
        return inode.type


def obsolete_inode(inodeScope, inodeName, account):
    """ obsoletes an inode

    :param inodeScope: the scope of the inode. The parameter does not do wildcard searches.
    :param inodeName: the name of the inode. The parameter does not do wildcard searches.
    :param account: the account that is requesting this operation.
    :raise DatasetObsolete: inode is a dataset which is already obsolete
    :raise FileObsolete: inode is a file which is already obsolete
    """

    if get_inode_type(inodeScope, inodeName, account) == InodeType.FILE:
        obsolete_file(inodeScope, inodeName, account)
    else:
        try:
            obsolete_dataset(inodeScope, inodeName, account)
        except exception.DatasetNotFound:  # As we don't know whether it was intended to be a dataset or a file
            raise exception.InodeNotFound('Target inode (%s) in scope (%s) does not exist.' % (inodeScope, inodeName))


def change_inode_owner(inodeScope, inodeName, oldAccount, newAccount):
    """ Change a dataset's owner

    :param inodeScope: the scope of the dataset
    :param inodeName: the name of the dataset
    :param oldAccount: the owner of the dataset
    :param newAccount: the new owner of the dataset
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise InodeNotFound: specified inode does not exist
    :raise DatasetObsolete: specified dataset does not exist
    :raise FileObsolete: specified file does not exist
    """

    try:
        inode_type = session.query(INODE).filter_by(scope=inodeScope, label=inodeName, owner=oldAccount, obsolete=False).one().type
    except NoResultFound, error:
        if error.args[0] == 'No row was found for one()':
            if not check_scope(inodeScope):  # check that scope exists
                raise exception.ScopeNotFound("Scope (%s) does not exist" % inodeScope)
            elif not account_exists(oldAccount):  # check that account specified exists
                raise exception.AccountNotFound("Account (%s) does not exist" % oldAccount)
            else:
                inode_info = get_inode_metadata(inodeScope, inodeName, oldAccount)
                if inode_info is None:
                    raise exception.InodeNotFound("Inode (%s) does not exist" % inodeName)
                elif inode_info['obsolete'] == True:  # check that specified dataset is not obsolete
                    if get_inode_type(inodeScope, inodeName, oldAccount) == InodeType.DATASET:
                        raise exception.DatasetObsolete("Dataset (%s) in scope (%s) is obsolete" % (inodeName, inodeScope))
                    else:
                        raise exception.FileObsolete("File (%s) in scope (%s) is obsolete" % (inodeName, inodeScope))
                else:
                    raise exception.NoPermissions("Specified account (%s) is not the owner" % oldAccount)
        else:
            exception.RucioException(error.args[0])
    if inode_type == InodeType.DATASET:
        change_dataset_owner(inodeScope, inodeName, oldAccount, newAccount)
    else:
        change_file_owner(inodeScope, inodeName, oldAccount, newAccount)


def list_inodes(accountName, inodeScope=None, inodeName=None, obsolete=False):
    """ lists inodes matching wildcard search.

    :param accountName: the account searching for the inodes.
    :param inodeScope: the scope where the inodes exists. This parameter accepts wildcards.
    :param inodeName: inodeName pattern. This parameter accepts wildcards.
    """

    if inodeScope is not None:
        inodeScope = inodeScope.replace("*", "%")
    if inodeName is not None:
        inodeName = inodeName.replace("*", "%")

    if inodeScope == '%':
        inodeScope = None
    if inodeName == '%':
        inodeName = None

    inode_query = session.query(INODE)
    # No scope
    if inodeScope is None:
        if inodeName is None:  # No node defined
            inodes = inode_query.all() if obsolete else inode_query.all(obsolete=False)
        elif '%' not in inodeName:  # No wildcards in inode name
            inodes = inode_query.filter_by(label=inodeName) if obsolete else inode_query.filter_by(label=inodeName, obsolete=False)
        else:  # Dataset wild card search
            inodes = inode_query.filter(INODE.label.like(inodeName)) if obsolete else inode_query.filter(INODE.label.like(inodeName)).filter_by(obsolete=False)
    # Scope has wildcards
    elif '%' in inodeScope:
        if inodeName is None:  # No inode defined
            inodes = inode_query.filter(INODE.scope.like(inodeScope)) if obsolete else inode_query.filter(INODE.scope.like(inodeScope))
        elif '%' not in inodeName:  # No wildcards in inode name
            inodes = inode_query.filter(INODE.scope.like(inodeScope)).filter_by(label=inodeName).all() if obsolete else inode_query.filter(INODE.scope.like(inodeScope)).filter_by(label=inodeName).filter_by(obsolete=False)
        else:  # Inode wildcard card search
            if obsolete:
                inodes = inode_query.filter(INODE.scope.like(inodeScope)).filter(INODE.label.like(inodeName))
            else:
                inodes = inode_query.filter(INODE.scope.like(inodeScope)).filter(INODE.label.like(inodeName)).filter_by(obsolete=False)
    # Single scope search
    else:
        if inodeName is None:  # No inode defined
            inodes = inode_query.filter_by(scope=inodeScope) if obsolete else inode_query.filter_by(scope=inodeScope, obsolete=False)
        elif '%' not in inodeName:  # No wildcards in inode name
            inodes = inode_query.filter_by(scope=inodeScope, label=inodeName) if obsolete else inode_query.filter_by(scope=inodeScope, label=inodeName, obsolete=False)
        else:  # Wildcards in inode name
            inodes = inode_query.filter_by(scope=inodeScope).filter(INODE.label.like(inodeName)) if obsolete else inode_query.filter_by(scope=inodeScope).filter(INODE.label.like(inodeName)).filter_by(obsolete=False)
    return [inode.label for inode in inodes]


def inode_list_generator(scope, listOfNames):
    """ Utility function. Takes a list of names and a scope parameter and generates (scope, name) tuples

    :param scope: The scope of the inode
    :param listOfNames: A list of inode names
    :returns: Yields inode tuples (label, name)
    """

    for name in listOfNames:
        yield (scope, name)


def build_inode_list(scope, listOfNames):
    """ Utility function. Takes a list of names and a scope parameter and generates a list of (scope, name) tuples

    :param scope: The scope of the inode
    :param listOfNames: A list of inode names
    :returns: A list of tuple [(label1, name1), (label2, name2), ...]
    """

    inode_list = []
    for name in listOfNames:
        inode_list.append((scope, name))
    return inode_list
