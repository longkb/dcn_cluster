# Copyright 2016 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""add vnfcluster

Revision ID: 89034eae4815
Revises: 0ae5b1ce3024
Create Date: 2016-11-01 10:48:42.112768

"""

# revision identifiers, used by Alembic.
revision = '89034eae4815'
down_revision = '0ae5b1ce3024'

from alembic import op
import sqlalchemy as sa


from tacker.db import migration


def upgrade(active_plugins=None, options=None):

    op.create_table(
        'vnfclusters',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('vnfd_id', sa.String(length=36), nullable=False),
        sa.Column('active', sa.Integer, nullable=False),
        sa.Column('standby', sa.Integer, nullable=False),
        sa.Column('policy_info', Json),
        sa.Column('status', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )

    op.create_table(
        'vnfclustermembers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('cluster_id', sa.String(length=36), nullable=False),
        sa.Column('index', sa.Integer, nullable=False),
        sa.Column('role', sa.String(length=255), nullable=False),
        sa.Column('vnf_info', Json),
        sa.ForeignKeyConstraint(['cluster_id'], ['vnfclusters.id'], ),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )