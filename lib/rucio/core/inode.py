# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import check_account, get_account
from rucio.core.scope import check_scope
from rucio.db.models1 import Dataset as DATASET
from rucio.db.models1 import Inode as INODE
from rucio.db.models1 import File as FILE
from rucio.db.models1 import InodeType
from rucio.db.session import get_session

session = get_session()

# DATASET FUNCTIONALITY


def register_dataset(scope, datasetName, account):
    """ create a new dataset.

    :param account: the owner who is creating the dataset
    :param scope: the namespace where this dataset belongs
    :param datasetName: the name of the dataset to be created
    :returns: nothing
    """
    new_inode = INODE()
    new_dataset = DATASET()
    new_inode.update({'scope': scope, 'label': datasetName, 'type': InodeType.DATASET, 'owner': account})
    new_dataset.update({'dsn': datasetName, 'scope': scope, 'owner': account})
    session.add(new_inode)
    session.add(new_dataset)
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_scope(scope):  # Maybe a valid scope does not exist
                raise exception.ScopeNotFound("Scope (%s) does not exist" % scope)
            elif not check_account(account):  # or non existing account was provided
                raise exception.AccountNotFound("Account (%s) does not exist" % account)
            elif not session.query(INODE).filter_by(scope=datasetScope, label=datasetName).first():
                raise exception.InodeNotFound("Inode not found (scope: %s, name: %s)" % (scope, name))
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
    dsts.filter_by(scope=scope, dsn=datasetName).delete()
    inds.filter_by(scope=scope, label=datasetName).delete()
    session.commit()


def check_dataset(datasetScope, datasetName, accountName):
    """ checks to see if dataset exists.

    :param accountName: the account searching for the dataset.
    :param datasetScope: the scope of the dataset. This parameter does not do wildcard searches.
    :param datasetName: the name of the dataset. This parameter does not do wildcard searches.
    """

    datasetScope.replace('*', '%')
    if session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName).first():
        return True
    else:
        return False


def list_datasets(accountName, datasetScope=None, datasetName=None):
    """ lists datasets matching wildcard search.

    :param accountName: the account searching for the datasets.
    :param datasetScope: the scope where the dataset exists. This parameter accepts wildcards.
    :param datasetName: the list of datasets. This parameter accepts wildcards.
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
            for dst in dst_query.all():
                datasets.append(dst.dsn)
        elif '%' not in datasetName:  # No wildcards in dataset name
            for dst in dst_query.filter_by(dsn=datasetName):
                datasets.append(dst.dsn)
        else:  # Dataset wild card search
            for dst in dst_query.filter(DATASET.dsn.like(datasetName)):
                datasets.append(dst.dsn)
    #  Scope has wildcards
    elif '%' in datasetScope:
        if datasetName is None:  # No dataset defined
            for dst in dst_query.filter(DATASET.scope.like(datasetScope)):
                datasets.append(dst.dsn)
        elif '%' not in datasetName:  # No wildcards in dataset name
            for dst in dst_query.filter(DATASET.scope.like(datasetScope)).filter_by(dsn=datasetName).all():
                datasets.append(dst.dsn)
        else:  # Dataset wildcard card search
            for dst in dst_query.filter(DATASET.scope.like(datasetScope)).filter(DATASET.dsn.like(datasetName)):
                datasets.append(dst.dsn)
    # Single scope search
    else:
        if datasetName is None:  # No dataset defined
            for dst in dst_query.filter_by(scope=datasetScope):
                datasets.append(dst.dsn)
        elif '%' not in datasetName:  # No wildcards in dataset name
            for dst in dst_query.filter_by(scope=datasetScope, dsn=datasetName):
                datasets.append(dst.dsn)
        else:  # Wildcards in dataset name
            for dst in dst_query.filter_by(scope=datasetScope).filter(DATASET.dsn.like(datasetName)):
                datasets.append(dst.dsn)
    return datasets


def change_dataset_owner(datasetScope, datasetName, oldAccount, newAccount):
    """ Change a dataset's owner

    :param datasetScope: the scope of the dataset
    :param datasetName: the name of the dataset
    :param oldAccount: the owner of the dataset
    :param newAccount: the new owner of the dataset
    """

    try:
        session.query(DATASET).filter_by(scope=datasetScope, dsn=datasetName, owner=oldAccount).one().update({'owner': newAccount})
        session.query(INODE).filter_by(scope=datasetScope, label=datasetName, owner=oldAccount).one().update({'owner': newAccount})
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(datasetScope):  # check that scope exists
                raise exception.ScopeNotFound("Scope (%s) does not exist" % datasetScope)
            elif not check_account(oldAccount):  # check that account specified exists
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
                    raise exception.NoPermisions("Specified account (%s) is not the owner" % oldAccount)
        else:
            exception.RucioException(error.args[0])
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_account(newAccount):  # check if non existing account was provided
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
    """

    try:
        dst_info = session.query(INODE).filter_by(scope=datasetScope, label=datasetName, type=InodeType.DATASET).one()
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(datasetScope):  # check if non existing account was provided
                raise exception.ScopeNotFound("Scope (%s) does not exist" % datasetScope)
            elif not get_inode_metadata(datasetScope, datasetName, account):
                raise exception.DatasetNotFound("Dataset (%s) does not exist in scope (%s)" % (datasetName, datasetScope))
            else:
                raise exception.RucioException(error.args[0])
        else:
            raise exception.RucioException(error.args[0])
    dictionary = {'owner': dst_info.owner, 'obsolete': dst_info.obsolete}
    return dictionary

# FILE FUNCTIONALITY


def register_file(scope, filename, account):
    """ register a new dataset.

    :param account: the owner who is creating the file
    :param scope: the namespace where this file belongs
    :param name: the name of the file to be created
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
            elif not check_account(account):  # If not then maybe a non existing account was specified
                raise exception.AccountNotFound("Account (%s) does not exist" % account)
            else:
                raise exception.RucioException(error.args[0])
        elif error.args[0] == "(IntegrityError) columns scope, label are not unique":
            if session.query(INODE).filter_by(scope=scope, label=filename).first().type == InodeType.DATASET:
                raise exception.DatasetAlreadyExists('Dataset with same name (%s) already exists in scope (%s)' % (filename, scope))
            else:
                raise exception.FileAlreadyExists('Filename with same name (%s) already exists in scope (%s)' % (filename, scope))
        elif error.args[0] == "(IntegrityError) columns scope, lfn are not unique":
            raise exception.FileAlreadyExists("File '%s' already exists in scope '%s'" % (filename, scope))
        else:
            raise exception.RucioException(error.args[0])


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
    """ unregister a file from the system. this functionality is not exposed to users and used only for development purposes.

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


def check_file(scope, filename, account):
    """ checks to see if dataset exists.

    :param accountName: the account searching for the file.
    :param scope: the scope where the file exists. This parameter does not do wildcard searches.
    :param filename: the name of the file. This parameter does not do wildcard searches.
    """

    session = get_session()

    return True if session.query(FILE).filter_by(scope=scope, lfn=filename).first() else False


def list_files(account, scope=None, filename=None):
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
    files = []
    # No scope
    if scope is None:
        if filename is None:  # No dataset defined
            for f in file_query.all():
                files.append(f.lfn)
        elif '%' not in filename:  # No wildcards in dataset name
            for f in file_query.filter_by(lfn=filename):
                files.append(f.lfn)
        else:  # Dataset wild card search
            for f in file_query.filter(FILE.lfn.like(filename)):
                files.append(f.lfn)
    #  Scope has wildcards
    elif '%' in scope:
        if filename is None:  # No dataset defined
            for f in file_query.filter(FILE.scope.like(scope)):
                files.append(f.lfn)
        elif '%' not in filename:  # No wildcards in dataset name
            for f in file_query.filter(FILE.scope.like(scope)).filter_by(lfn=filename).all():
                files.append(f.lfn)
        else:  # Dataset wildcard card search
            for f in file_query.filter(FILE.scope.like(scope)).filter(FILE.lfn.like(filename)):
                files.append(f.lfn)
    # Single scope search
    else:
        if filename is None:  # No dataset defined
            for f in file_query.filter_by(scope=scope):
                files.append(f.lfn)
        elif '%' not in filename:  # No wildcards in dataset name
            for f in file_query.filter_by(scope=scope, lfn=filename):
                files.append(f.lfn)
        else:  # Wildcards in dataset name
            for f in file_query.filter_by(scope=scope).filter(FILE.lfn.like(filename)):
                files.append(f.lfn)
    return files


def change_file_owner(fileScope, filename, oldAccount, newAccount):
    """ Change a file's owner

    :param fileScope: the scope of the file
    :param filename: the name of the file
    :param oldAccount: the owner of the file
    :param newAccount: the new owner of the file
    """

    try:
        session.query(FILE).filter_by(scope=fileScope, lfn=filename, owner=oldAccount).one().update({'owner': newAccount})
        session.query(INODE).filter_by(scope=fileScope, label=filename, owner=oldAccount).one().update({'owner': newAccount})
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(fileScope):  # check that scope exists
                raise exception.ScopeNotFound("Scope (%s) does not exist" % fileScope)
            elif not check_account(oldAccount):  # check that account specified exists
                raise exception.AccountNotFound("Account (%s) does not exist" % oldAccount)
            else:  # if account and scope exist then check to see if scope+name are registered as a file
                inode_info = get_inode_metadata(fileScope, filename, oldAccount)
                if inode_info is None:
                    raise exception.FileNotFound("File (%s) does not exist" % filename)
                elif inode_info['type'] == InodeType.DATASET:  # check if specified file is actually a dataset
                    raise exception.NotAFile("Specified dsn (%s) in scope (%s) is actually a dataset" % (filename, fileScope))
                elif inode_info['obsolete'] == True:  # check that specified dataset is not obsolete
                    raise exception.DatasetObsolete("File (%s) in scope (%s) is obsolete" % (filename, fileScope))
                else:
                    raise exception.NoPermisions("Specified account (%s) is not the owner" % oldAccount)
        else:
            exception.RucioException(error.args[0])
    try:
        session.commit()
    except IntegrityError, error:
        session.rollback()
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_account(newAccount):  # check if non existing account was provided
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
    """

    try:
        dst_info = session.query(INODE).filter_by(scope=fileScope, label=filename, type=InodeType.FILE).one()
    except NoResultFound, error:
        session.rollback()
        if error.args[0] == 'No row was found for one()':
            if not check_scope(fileScope):  # check if non existing account was provided
                raise exception.ScopeNotFound("Scope (%s) does not exist" % fileScope)
            elif not query_inode(fileScope, filename, account):
                raise exception.DatasetNotFound("File (%s) does not exist in scope (%s)" % (filename, fileScope))
            else:
                raise exception.RucioException(error.args[0])
        else:
            raise exception.RucioException(error.args[0])
    dictionary = {'owner': dst_info.owner, 'obsolete': dst_info.obsolete}
    return dictionary


# INODE FUNCTIONALITY

def check_inode(scope, name, account):
    """ checks to see if inode exists.

    :param account: the account searching for the file.
    :param scope: the scope where the inode exists. This parameter does not do wildcard searches.
    :param name: the name of the inode. This parameter does not do wildcard searches.
    :returns: True if inode exists, otherwise False
    """

    return True if session.query(INODE).filter_by(scope=scope, label=name).first() else False


def get_inode_metadata(inodeScope, inodeName, account):
    """ Check if the inode exists

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
        return {'type': inode.type, 'obsolete': inode.obsolete, 'owner': inode.owner}


def change_inode_owner(inodeScope, inodeName, oldAccount, newAccount):
    """ Change a dataset's owner

    :param inodeScope: the scope of the dataset
    :param inodeName: the name of the dataset
    :param oldAccount: the owner of the dataset
    :param newAccount: the new owner of the dataset
    """

    try:
        inode_type = session.query(INODE).filter_by(scope=inodeScope, label=inodeName, owner=oldAccount, obsolete=False).one().type
    except NoResultFound, error:
        if error.args[0] == 'No row was found for one()':
            if not check_scope(inodeScope):  # check that scope exists
                raise exception.ScopeNotFound("Scope (%s) does not exist" % inodeScope)
            elif not check_account(oldAccount):  # check that account specified exists
                raise exception.AccountNotFound("Account (%s) does not exist" % oldAccount)
            else:
                inode_info = get_inode_metadata(inodeScope, inodeName, oldAccount)
                if inode_info is None:
                    raise exception.DatasetNotFound("Inode (%s) does not exist" % inodeName)
                elif inode_info['obsolete'] == True:  # check that specified dataset is not obsolete
                    raise exception.DatasetObsolete("Inode (%s) in scope (%s) is obsolete" % (inodeName, inodeScope))
                else:
                    raise exception.NoPermisions("Specified account (%s) is not the owner" % oldAccount)
        else:
            exception.RucioException(error.args[0])
    if inode_type == InodeType.DATASET:
        change_dataset_owner(inodeScope, inodeName, oldAccount, newAccount)
    else:
        change_file_owner(inodeScope, inodeName, oldAccount, newAccount)


def list_inodes(accountName, inodeScope=None, inodeName=None):
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
    inodes = []
    # No scope
    if inodeScope is None:
        if inodeName is None:  # No node defined
            for ind in inode_query.all():
                inodes.append(ind.label)
        elif '%' not in inodeName:  # No wildcards in inode name
            for ind in inode_query.filter_by(label=inodeName):
                inodes.append(ind.label)
        else:  # Dataset wild card search
            for ind in inode_query.filter(INODE.label.like(inodeName)):
                inodes.append(ind.label)
    # Scope has wildcards
    elif '%' in inodeScope:
        if inodeName is None:  # No inode defined
            for ind in inode_query.filter(INODE.scope.like(inodeScope)):
                inodes.append(ind.label)
        elif '%' not in inodeName:  # No wildcards in inode name
            for ind in inode_query.filter(INODE.scope.like(inodeScope)).filter_by(label=inodeName).all():
                inodes.append(ind.label)
        else:  # Inode wildcard card search
            for ind in inode_query.filter(INODE.scope.like(inodeScope)).filter(INODE.label.like(inodeName)):
                inodes.append(ind.label)
    # Single scope search
    else:
        if inodeName is None:  # No inode defined
            for ind in inode_query.filter_by(scope=inodeScope):
                inodes.append(ind.label)
        elif '%' not in inodeName:  # No wildcards in inode name
            for ind in inode_query.filter_by(scope=inodeScope, label=inodeName):
                inodes.append(ind.label)
        else:  # Wildcards in inode name
            for ind in inode_query.filter_by(scope=inodeScope).filter(INODE.label.like(inodeName)):
                inodes.append(ind.label)
    return inodes
