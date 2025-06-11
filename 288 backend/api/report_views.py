from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Report

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_reports(request):
    try:
        print("Received request data:", request.data)  # للتأكد من البيانات المستلمة
        ids = request.data.get('ids', [])
        print("Extracted IDs:", ids)  # للتأكد من استخراج الـ IDs
        
        if not isinstance(ids, list) or not ids:
            return Response({'error': 'No IDs provided.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # التحقق من وجود التقارير
        reports = Report.objects.filter(id__in=ids)
        if not reports.exists():
            return Response({'error': 'No reports found with the provided IDs.'}, status=status.HTTP_404_NOT_FOUND)
        
        # حذف التقارير
        deleted_count, _ = reports.delete()
        
        return Response({
            'success': True,
            'message': f'Successfully deleted {deleted_count} reports.',
            'deleted_count': deleted_count
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print("Error in delete_reports:", str(e))  # للتأكد من أي أخطاء
        return Response({
            'error': f'Failed to delete reports: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 