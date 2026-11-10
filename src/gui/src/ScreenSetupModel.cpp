/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ScreenSetupModel.h"
#include "Screen.h"

#include <QtCore>
#include <QtGui>

const QString ScreenSetupModel::m_MimeType = "application/x-qbarrier-screen";

ScreenSetupModel::ScreenSetupModel(std::vector<Screen>& screens, int numColumns, int numRows) :
    QAbstractTableModel(NULL),
    m_Screens(screens),
    m_NumColumns(numColumns),
    m_NumRows(numRows)
{
    if (m_NumColumns * m_NumRows > screens.size())
        qFatal("Not enough elements (%u) in screens QList for %d columns and %d rows", screens.size(), m_NumColumns, m_NumRows);
}

QVariant ScreenSetupModel::data(const QModelIndex& index, int role) const
{
    if (index.isValid() && index.row() < m_NumRows && index.column() < m_NumColumns)
    {
        switch(role)
        {
            case Qt::DecorationRole:
                if (screen(index).isNull())
                    break;
                return QIcon(*screen(index).pixmap());

            case Qt::ToolTipRole:
                if (screen(index).isNull())
                    break;
                return QString(tr(
                            "<center>Screen: <b>%1</b></center>"
                            "<br>Double click to edit settings"
                            "<br>Drag screen to the trashcan to remove it")).arg(screen(index).name());

            case Qt::DisplayRole:
                if (screen(index).isNull())
                    break;
                return screen(index).name();
        }
    }

    return QVariant();
}

Qt::ItemFlags ScreenSetupModel::flags(const QModelIndex& index) const
{
    if (!index.isValid() || index.row() >= m_NumRows || index.column() >= m_NumColumns)
        return {};

    if (!screen(index).isNull())
        return Qt::ItemIsEnabled | Qt::ItemIsDragEnabled | Qt::ItemIsSelectable | Qt::ItemIsDropEnabled;

    return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDropEnabled;
}

Qt::DropActions ScreenSetupModel::supportedDropActions() const
{
    return Qt::MoveAction | Qt::CopyAction;
}

QStringList ScreenSetupModel::mimeTypes() const
{
    return QStringList() << m_MimeType;
}

QMimeData* ScreenSetupModel::mimeData(const QModelIndexList& indexes) const
{
    QMimeData* pMimeData = new QMimeData();
    QByteArray encodedData;

    QDataStream stream(&encodedData, QIODevice::WriteOnly);

    for (const QModelIndex& index : indexes) {
        if (index.isValid())
            stream << index.column() << index.row() << screen(index);
    }

    pMimeData->setData(m_MimeType, encodedData);

    return pMimeData;
}

bool ScreenSetupModel::dropMimeData(const QMimeData* data, Qt::DropAction action, int row, int column, const QModelIndex& parent)
{
    if (action == Qt::IgnoreAction) { return true; }
    if (action != Qt::MoveAction && action != Qt::CopyAction) { return false; }

    if (!data->hasFormat(m_MimeType))
        return false;

     if (!parent.isValid() || parent.model() != this || parent.row() < 0 || parent.column() < 0 ||
         parent.row() >= m_NumRows || parent.column() >= m_NumColumns || row != -1 || column != -1)
        return false;

    QByteArray encodedData = data->data(m_MimeType);
    if (encodedData.isEmpty() || encodedData.size() > 32768) { return false; }
    QDataStream stream(&encodedData, QIODevice::ReadOnly);
    stream.setVersion(QDataStream::Qt_5_15);

    int sourceColumn = -1;
    int sourceRow = -1;

    stream >> sourceColumn;
    stream >> sourceRow;

    const bool external = sourceColumn == -1 && sourceRow == -1;
    if (!external && (sourceColumn < 0 || sourceRow < 0 || sourceColumn >= m_NumColumns || sourceRow >= m_NumRows)) {
        return false;
    }
    // don't drop screen onto itself
    if (sourceColumn == parent.column() && sourceRow == parent.row())
        return false;

    Screen droppedScreen;
    stream >> droppedScreen;
    if (stream.status() != QDataStream::Ok || droppedScreen.isNull() || !stream.atEnd()) { return false; }

    Screen oldScreen = screen(parent.column(), parent.row());
    // I enforce the view's rules here as well; MIME coordinates aren't authority.
    if (external) {
        if (action != Qt::CopyAction || !oldScreen.isNull()) { return false; }
    } else {
        if (action != Qt::MoveAction || screen(sourceColumn, sourceRow).isNull()) { return false; }
        QByteArray actual, supplied;
        QDataStream actualStream(&actual, QIODevice::WriteOnly);
        QDataStream suppliedStream(&supplied, QIODevice::WriteOnly);
        actualStream << screen(sourceColumn, sourceRow);
        suppliedStream << droppedScreen;
        if (actual != supplied) { return false; }
    }
    if (!oldScreen.isNull() && !external)
    {
        // mark the screen so it isn't deleted after the dragndrop succeeded
        // see ScreenSetupView::startDrag()
        oldScreen.setSwapped(true);
        screen(sourceColumn, sourceRow) = oldScreen;
    }

    screen(parent.column(), parent.row()) = droppedScreen;

    return true;
}
