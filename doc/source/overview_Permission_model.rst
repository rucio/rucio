----------------
Permission model 
----------------

Rucio assigns permissions to accounts. Permissions are boolean flags designating 
whether an account may perform a certain action (read, write, delete) on a resource (RSE, account, replica, etc.).

Rucio comes with a generic permission policy including a typical set of permissions. This policy can be replaced with a
more fitting permission file representing the policies of the community using Rucio.
