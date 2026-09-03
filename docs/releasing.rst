=========
Releasing
=========

Publishing is by Trusted Publishing (OIDC): no API token is stored anywhere.
``.github/workflows/release-python.yml`` builds an sdist and a wheel on a
version tag push and uploads them.

One-time provisioning
=====================

Both steps are on the account side and have to be done before the first
release.

**1. PyPI pending publisher.** c65of does not exist on PyPI yet, so add it at
https://pypi.org/manage/account/publishing/ as a *pending* publisher:

============================ ====================
PyPI project name            ``c65of``
Owner                        ``c65sdn``
Repository name              ``c65of``
Workflow name                ``release-python.yml``
Environment name             ``release``
============================ ====================

The project is created on the first successful upload.

**2. GitHub environment.** Ensure an environment named ``release`` exists
under Settings -> Environments in ``c65sdn/c65of``, as ``c65sdn/faucet``
already has. The environment name has to match what PyPI was told, exactly.

Cutting a release
=================

The version comes from the git tag: pbr runs ``git describe``, so the tag is
the only place a version number is written.

.. code:: bash

    git tag 1.0.0
    git push origin 1.0.0

The workflow triggers on tags matching ``[0-9]+.[0-9]+.[0-9]+``, checks out
full history so pbr can see the tag, builds, and refuses to publish if the
built filename does not match the tag. An untagged build produces a
``.devN`` version, which that check rejects.

Verified locally: tagging ``1.0.0`` produces ``c65of-1.0.0.tar.gz`` and
``c65of-1.0.0-py3-none-any.whl``, and the sdist installs into a clean
virtualenv reporting version ``1.0.0`` with no third party module in
``sys.modules``.
